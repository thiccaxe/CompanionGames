import asyncio
import logging

import websockets

from server_data import ServerData


class WebsocketServer:

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data: ServerData):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._data = data
        self._websocket_server = websockets.serve(self.handler, "", int(self._config["server"]["websocket_port"]), loop=self._loop)

    async def handler(self, websocket: websockets.WebSocketClientProtocol):
        while True:
            message = await websocket.recv()
            logging.debug(message)

    async def __aenter__(self):
        if self._websocket_server is not None:
            logging.debug(f"Starting websocket server")
            return await self._websocket_server.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._websocket_server is not None:
            logging.debug(f"Stopping websocket server")
            return await self._websocket_server.__aexit__(exc_type, exc_val, exc_tb)

