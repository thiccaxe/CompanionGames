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
import os

from companion_manager import CompanionManager
from companion_server import CompanionServer
from config import Config, ConfigurationLoadError
from logger import setup_logging
from mdns_registration import CompanionGamesZeroconf
from server_data import ServerData
from wayland_input import WaylandInput
from websocket_server import WebsocketServer


class CompanionGames:

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._mdns = CompanionGamesZeroconf(self._config)
        self._data = ServerData()
        self._manager = CompanionManager(self._config, self._secrets, self._loop, self._data)
        self._websocket_server = WebsocketServer(self._config, self._secrets, self._loop, self._data, self._manager)
        self._companion_server = CompanionServer(self._config, self._secrets, self._loop, self._data, self._manager)
        self._wayland_input = WaylandInput(self._loop)
        self._manager._wayland_input = self._wayland_input

    async def handler(self, websocket):
        while True:
            message = await websocket.recv()
            logging.debug(message)

    async def begin(self):
        logging.info("Starting Companion Games Server")
        async with self._wayland_input:
            logging.info("Starting MDNS")
            async with self._mdns:
                logging.info("Starting Companion Games Websocket Server")
                async with self._websocket_server:
                    logging.info("Starting Companion Games Companion Server")
                    async with self._companion_server:
                        try:
                            logging.info("Ctrl^C to quit")
                            while True:
                                await asyncio.sleep(1)
                        except asyncio.CancelledError:
                            logging.info("Cancelled ...")
                        except KeyboardInterrupt:
                            logging.info("Cancelled ...")
                        finally:
                            logging.info("Stopping Server ...")


async def main():
    logging.info("Starting companion games ...")

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
