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
import json
import logging

import websockets
from websockets.server import State as WebsocketState

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

    async def handler(self, websocket: websockets.WebSocketServerProtocol):
        await self._manager.website_connected(websocket)
        try:
            running = True
            shutdown_wait_task = asyncio.create_task(self._data.shutdown_event.wait())
            while running:
                done, pending = await asyncio.wait(
                    [asyncio.create_task(websocket.recv()), shutdown_wait_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # shutdown case
                if self._data.shutdown_event.is_set():
                    running = False
                    await self._manager.website_disconnected()
                    await websocket.close()
                    return  # OK to return

                if websocket.state == WebsocketState.CLOSING or websocket.state == WebsocketState.CLOSED:
                    running = False
                    logging.info("'Task exception was never retrieved' warning can be safely ignored")
                    break

                # assume message in done
                if len(done) != 1:
                    logging.warning(f"{len(done)} tasks returned, only should have been one at this point")
                    running = False
                    break  # some error
                message_coro, = done
                message = await message_coro
                if isinstance(message, str):
                    await self._parse_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            logging.debug(f"Websocket connection closed")

        await self._manager.website_disconnected()

    async def _parse_message(self, websocket: websockets.WebSocketServerProtocol, message: str):
        try:
            packet = json.loads(message)
            logging.debug(f"Received message: {packet}")
            if ("id" not in packet) or ("event" not in packet):
                logging.warning(f"Malformed packet - no event")
                return
            await self._handle_packet(websocket, packet)

        except json.JSONDecodeError as e:
            logging.warning(f"WebSocket sent non-JSON data; details:")
            logging.exception(e)

    async def _handle_packet(self, websocket: websockets.WebSocketServerProtocol, packet: dict) -> None:
        if packet["event"] == "companion_games:event/device/list/connected":
            await self._manager.send_to_website({
                "id": packet["id"],
                "event": "companion_games:event/device/list/connected",
                "data": [hdpid for hdpid in self._data.connected_clients]
            })
            return
        elif packet["event"] == "companion_games:event/device/action/disconnect":
            if not ("data" in packet and isinstance(packet["data"], str)):
                await self._manager.send_to_website({
                    "id": packet["id"],
                    "event": "companion_games:event/error/malformed_request"
                })
                return

            hdpid = packet["data"]
            if hdpid not in self._data.connected_clients:
                await self._manager.send_to_website({
                    "id": packet["id"],
                    "event": "companion_games:event/error/device/not_connected"
                })
                return

            await self._manager.disconnect_device(hdpid)
            await self._manager.send_to_website({
                "id": packet["id"],
                "event": "companion_games:event/successish/device/disconnected"
            })
            return

    async def __aenter__(self):
        if self._websocket_server is not None:
            logging.debug(f"Starting websocket server")
            return await self._websocket_server.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._websocket_server is not None:
            logging.debug(f"Stopping websocket server")
            return await self._websocket_server.__aexit__(exc_type, exc_val, exc_tb)
