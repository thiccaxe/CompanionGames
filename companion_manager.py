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
import logging
import random

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

    def set_websocket_server(self, websocket_server):
        self._websocket_server = websocket_server

    def set_companion_server(self, companion_server):
        self._companion_server = companion_server

    async def companion_device_paired(self, hdpid, pairing):
        # save
        self._secrets["clients"][hdpid] = pairing
        pass  # notify website?

    async def companion_device_connected(self, hdpid, protocol):
        if hdpid in self._data.connected_clients:
            pass  # kick old client, smoothly migrate without with troubling website. simply send an update about this
            logging.debug(f"Companion device with ({hdpid=}) replacing old one")

        else:  # new client connected
            self._data.connected_clients[hdpid] = protocol
            logging.debug(f"Companion device with ({hdpid=}) connected")
            pass

    async def companion_device_disconnected(self, hdpid):
        if hdpid in self._data.connected_clients:
            del self._data.connected_clients[hdpid]
            # notify website
            logging.debug(f"Companion device ({hdpid=}) connected")
        else:
            logging.warning(f"Disconnected a client with {hdpid=} when it never was connected!")

    async def website_connected(self, websocket: websockets.WebSocketClientProtocol):
        self._data.websocket = websocket
        logging.debug("Website connected")

    async def website_disconnected(self):
        logging.debug("Website disconnected")

    async def temp_send_text(self, text):
        logging.debug(f"Broadcasting text {text}")
        for hdpid in copy.copy(self._data.connected_clients):
            typing_session = TypingSession(
                tsid=binascii.hexlify(random.randbytes(4)).decode("utf-8"),
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

        client.open_typing_session(typing_session)



