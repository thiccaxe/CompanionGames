import asyncio
import logging
import os
import sys

from logger import setup_logging
from config import Config, ConfigurationLoadError
from mdns_registration import CompanionGamesZeroconf, ZeroconfException


class CompanionGames:

    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop):
        self._config = config
        self._secrets = secrets
        self._loop = loop
        self._mdns = CompanionGamesZeroconf(self._config)

    async def begin(self):
        logging.info("Starting Companion Games Server")
        async with self._mdns:
            logging.info("Press ENTER to quit")
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
