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
import random
import uuid

import websockets

from server_data import ServerData, TypingSession

"""
All the shit goes down here
"""


class CompanionManager:
    _websocket_server: object
    _companion_server: object

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data: ServerData):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._data = data

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
