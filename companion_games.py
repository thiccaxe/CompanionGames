import asyncio
import logging
import os
import sys

import websockets

from companion_server import CompanionServer
from logger import setup_logging
from config import Config, ConfigurationLoadError
from mdns_registration import CompanionGamesZeroconf, ZeroconfException
from server_data import ServerData
from websocket_server import WebsocketServer


class CompanionGames:

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._mdns = CompanionGamesZeroconf(self._config)
        self._data = ServerData()
        self._websocket_server = WebsocketServer(self._config, self._secrets, loop, self._data)
        self._companion_server = CompanionServer(self._config, self._secrets, loop, self._data)

    async def handler(self, websocket):
        while True:
            message = await websocket.recv()
            logging.debug(message)

    async def begin(self):
        logging.info("Starting Companion Games Server")
        async with self._mdns:
            logging.info("Starting Companion Games Websocket Server")
            async with self._websocket_server:
                logging.info("Starting Companion Games Companion Server")
                async with self._companion_server:
                    print("Press ENTER to quit")
                    await self._loop.run_in_executor(None, sys.stdin.readline)


async def main():
    logging.info("Starting companion games...")

    config = Config(
        os.environ.get("COMPANION_GAMES_CONFIG", "./config.toml"),
        os.environ.get("COMPANION_GAMES_SECRETS", "./secrets.toml"),
    )
    loop = asyncio.get_event_loop()

    try:
        await config.initialize()

        companion_games = CompanionGames(config.config, config.secrets, loop)
        await companion_games.begin()
    except ConfigurationLoadError:
        logging.error("Could not load configuration. Exiting")
        return
    finally:
        await config.close()


if __name__ == "__main__":
    setup_logging()
    asyncio.run(main())
