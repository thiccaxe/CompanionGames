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
import logging

import websockets

from companion_manager import CompanionManager
from server_data import ServerData


class WebsocketServer:

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data: ServerData, manager: CompanionManager):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._data = data
        self._websocket_server = websockets.serve(self.handler, "", int(self._config["server"]["websocket_port"]),
                                                  loop=self._loop)
        self._manager = manager
        self._manager.set_websocket_server(self)

    async def handler(self, websocket: websockets.WebSocketClientProtocol):
        await self._manager.website_connected(websocket)
        try:
            while True:
                message = await websocket.recv()
                logging.debug(message)
                if isinstance(message, str):
                    await self._manager.temp_send_text(message.strip())
        except websockets.exceptions.ConnectionClosed:
            logging.debug(f"Websocket connection closed")

        await self._manager.website_disconnected()

    async def __aenter__(self):
        if self._websocket_server is not None:
            logging.debug(f"Starting websocket server")
            return await self._websocket_server.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._websocket_server is not None:
            logging.debug(f"Stopping websocket server")
            return await self._websocket_server.__aexit__(exc_type, exc_val, exc_tb)
