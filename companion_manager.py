"""
CompanionGames
Copyright (C) 2024 thiccaxe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import binascii
import copy
import json
import logging
import plistlib
UID = plistlib.UID
import random
import uuid
from pyatv.protocols.companion.protocol import (
    FrameType,
)

import websockets

from server_data import ServerData, TypingSession

"""
All the shit goes down here
"""


class CompanionManager:
    _websocket_server: object
    _companion_server: object
    _wayland_input: object

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data: ServerData):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._data = data
        self._debug_send_all_touch = False

    def get_current_pairing_session(self):
        pairings: dict = self._secrets["pairings"]
        for psid, pairing_session in pairings.items():
            if pairing_session["allow_pairing"] is True:
                return pairing_session

        return None

    def pairing_session_set_allow_pairing(self, psid, allow_pairing: bool):
        pairings: dict = self._secrets["pairings"]
        if psid not in pairings:
            logging.warning(f"Pairing session {psid=} does not exist")
            return False
        if allow_pairing:  # need to disable all others
            for pairing_session in pairings.values():
                pairing_session["allow_pairing"] = False
        pairings[psid]["allow_pairing"] = bool(allow_pairing)
        return True

    def pairing_session_delete(self, psid):
        pairings: dict = self._secrets["pairings"]
        if psid not in pairings:
            logging.warning(f"Pairing session {psid=} does not exist")
            return False
        del pairings[psid]

    def pairing_session_create(self, pairing_options: dict) -> dict:
        pairing = {k: v for k, v in pairing_options.items() if k in (
            "allow_pairing", "allow_connections", "admin"
        )}
        pairing.setdefault("allow_pairing", False)
        pairing.setdefault("allow_connections", True)
        pairing.setdefault("admin", False)
        pairing["pin"] = "{0:04}".format(random.randint(0, 9999))
        psid = uuid.uuid4().hex
        pairing["psid"] = psid

        self._secrets["pairings"][psid] = pairing

        return pairing

    def set_websocket_server(self, websocket_server):
        self._websocket_server = websocket_server

    def set_companion_server(self, companion_server):
        self._companion_server = companion_server

    async def companion_device_paired(self, hdpid, pairing):
        # save
        self._secrets["clients"][hdpid] = pairing

        # send to website
        await self.send_to_website({
            "event": "companion_games:event/device/paired",
            "hdpid": hdpid,
        })

    async def companion_device_connected(self, hdpid, protocol):
        if hdpid in self._data.connected_clients:
            pass  # kick old client, smoothly migrate without with troubling website. simply send an update about this
            logging.debug(f"Companion device with ({hdpid=}) replacing old one")

        else:  # new client connected
            self._data.connected_clients[hdpid] = protocol
            logging.debug(f"Companion device with ({hdpid=}) connected")
            pass

        # send to website
        await self.send_to_website({
            "event": "companion_games:event/device/connected",
            "hdpid": hdpid,
        })

    async def companion_device_disconnected(self, hdpid):
        if hdpid in self._data.connected_clients:
            del self._data.connected_clients[hdpid]
            # notify website
            logging.debug(f"Companion device ({hdpid=}) disconnected")
            # send to website
            await self.send_to_website({
                "event": "companion_games:event/device/disconnected",
                "hdpid": hdpid,
            })
        else:
            logging.warning(f"Disconnected a client with {hdpid=} when it never was connected!")

    async def disconnect_device(self, hdpid):
        if hdpid not in self._data.connected_clients:
            logging.warning(f"Attempted to disconnect a device that was not connected")
            return
        proto = self._data.connected_clients[hdpid]
        proto.close_transport()

    async def website_connected(self, websocket: websockets.WebSocketServerProtocol):
        self._data.connected_website = websocket
        logging.debug("Website connected")

    async def website_disconnected(self):
        self._data.connected_website = None
        logging.debug("Website disconnected")

    async def send_to_website(self, packet: dict):
        if not self._data.connected_website:
            logging.debug("Wanted to send data when website not connected")
            return
        packet.setdefault("id", random.randint(5_000_000, 2_000_000_000))
        await self._data.connected_website.send(json.dumps(packet))


    async def text_inserted(self, hdpid: str, inserted: str):
        for character in inserted:
            await self._wayland_input.key_press(character)
    async def text_delete_count(self, hdpid: str, delete_count: int):
        for _ in range(delete_count):
            await self._wayland_input.delete_char()
    async def on_hidc(self, hdpid: str, packet: dict):
        logging.debug(f"on_hidc {hdpid=} {packet=} {self._debug_send_all_touch}")
        content = packet.get("_c", {})
        hid_c, h_bts = content.get("_hidC", None), content.get("_hBtS", None)
        if hid_c == 6:
            if h_bts == 1:
                await self._wayland_input.lmb_down()
            elif h_bts == 2:
                await self._wayland_input.lmb_up()
        elif hid_c == 19:
            if h_bts == 2:
                await self._data.connected_clients[hdpid]._send_opack(FrameType.E_OPACK, {
                    '_i': '_tiStarted', '_x': random.randint(1, 1000),
                    '_c': {
                        '_tiV': 1,
                        '_tiD': plistlib.dumps({
                            '$version': 100000,
                            '$archiver': 'RTIKeyedArchiver',
                            '$top': {'documentTraits': UID(5), 'sessionUUID': UID(38), 'documentState': UID(1)}, '$objects': ['$null', {'docSt': UID(2), '$class': UID(4), 'originatedFromSource': False}, {'$class': UID(3)}, {'$classname': 'TIDocumentState', '$classes': ['TIDocumentState', 'NSObject']}, {'$classname': 'RTIDocumentState', '$classes': ['RTIDocumentState', 'NSObject']}, {'locApp': UID(8), 'a2bId': True, 'bId': UID(7), 'aId': UID(6), '$class': UID(37), 'cfmType': 87, 'traitsMask': 576, 'userInfo': UID(11), 'tiTraits': UID(9)}, '', 'com.apple.TVWatchList', 'TV', {'flags': 1417693830, 'auxFlags': 1, '$class': UID(10), 'version': 2}, {'$classname': 'TITextInputTraits', '$classes': ['TITextInputTraits', 'NSObject']}, {'NS.keys': [UID(12), UID(13), UID(14), UID(15), UID(16), UID(17), UID(18), UID(19), UID(20), UID(21), UID(22), UID(23), UID(24), UID(25), UID(26), UID(27), UID(28), UID(29)], 'NS.objects': [UID(30), UID(30), UID(31), UID(30), UID(32), UID(33), UID(30), UID(30), UID(30), UID(32), UID(30), UID(30), UID(30), UID(33), UID(33), UID(34), UID(33), UID(30)], '$class': UID(36)}, 'ShouldSuppressSoftwareKeyboard', 'ShouldSuppressSoftwareKeyboardForKeyboardCamera', 'RTIInputDelegateClassName', 'UseAutomaticEndpointing', 'ReturnKeyEnabled', 'ShouldUseDictationSearchFieldBehavior', 'SuppressSoftwareKeyboard', 'ForceFloatingKeyboard', 'HasCustomInputViewController', 'CorrectionLearningAllowed', 'SuppressAssistantBar', 'ForceDisableDictation', 'ForceEnableDictation', 'HasNextKeyResponder', 'InputViewHiddenCount', 'DisableBecomeFirstResponder', 'HasPreviousKeyResponder', 'AcceptsDictationResults', False, 'UISearchBarTextField', True, 0, {'NS.keys': [UID(35)], 'NS.objects': [UID(33)], '$class': UID(36)}, 'disabled', {'$classname': 'NSDictionary', '$classes': ['NSDictionary', 'NSObject']}, {'$classname': 'RTIDocumentTraits', '$classes': ['RTIDocumentTraits', 'NSObject']}, b'\xa3\xc2&u\xa30H\xb7\x99\x01\xcb\xd4L\xa0\xe48']
                        }, fmt=plistlib.FMT_BINARY)
                    },
                    "_t": 1
                })
        await self._wayland_input.deltas()
        if self._debug_send_all_touch:  
            await self.send_to_website({
                "event": "companion_games:event/device/interactions/hidc",
                "data": packet.get("_c", {})
            })

    async def on_hidt(self, hdpid: str, packet: dict):
        logging.debug(f"on_hidt {hdpid=} {packet=} {self._debug_send_all_touch}")
        content = packet.get("_c", {})
        dx, dy = content.get("_dx", None), content.get("_dy", None)
        if dx is not None or dy is not None:
            await self._wayland_input.deltas(dx, dy)
        if self._debug_send_all_touch:  
            await self.send_to_website({
                "event": "companion_games:event/device/interactions/hidt",
                "data": content
            })

    async def temp_send_text(self, text):
        logging.debug(f"Broadcasting text {text}")
        for hdpid in copy.copy(self._data.connected_clients):
            typing_session = TypingSession(
                tsid=uuid.uuid4(),
                meta={
                    "text": text,
                },
                hdpid=None
            )
            await self._assign_typing_session(typing_session, hdpid)

    async def _assign_typing_session(self, typing_session: TypingSession, hdpid: str):
        if hdpid not in self._data.connected_clients:
            logging.warning(f"Attempted to assign tsid={typing_session.tsid} to disconnected client {hdpid=}")
            return

        client = self._data.connected_clients[hdpid]

        typing_session.hdpid = hdpid

        await client.open_typing_session(typing_session)
