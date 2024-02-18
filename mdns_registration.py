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

import logging

import zeroconf
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceInfo


class ZeroconfManager:

    def __init__(self):
        self._zeroconf = AsyncZeroconf(ip_version=IPVersion.V4Only)

    async def register_service(self, service: AsyncServiceInfo):
        await self._zeroconf.async_register_service(service)

    async def unregister_service(self, service: AsyncServiceInfo):
        await self._zeroconf.async_unregister_service(service)

    async def unregister_all_services(self):
        await self._zeroconf.async_unregister_all_services()


class ZeroconfException(Exception): pass


class CompanionGamesZeroconf:
    _service: AsyncServiceInfo

    def __init__(self, config):
        self._manager = ZeroconfManager()
        self._config = config

    async def start(self):
        from _socket import inet_aton
        records = {
            "rpHA": "9948cfb6da55",  #
            "rpHN": "cef88e5db6fa",  #
            "rpAD": "3b2210518c58",  #
            "rpHI": "91756a18d8e5",  #
            "rpMd": "AppleTV5,3",  #
            "rpVr": "523.1.2",  #
            "rpMac": "2",  #
            "rpFl": "0XB6782",  #
            "rpBA": self._config['server']['mac'],  #
            "rpMRtID": self._config['server']['id'],  #
        }
        try:
            self._service = AsyncServiceInfo(
                "_companion-link._tcp.local.",
                f"{self._config['server']['name']}._companion-link._tcp.local.",
                addresses=[inet_aton("192.168.1.35")],
                port=int(self._config['server']['companion_port']),
                properties=records,
                server=f"{self._config['server']['name']}.local."
            )

            await self._manager.register_service(self._service)
            logging.debug(f"Registered services.")
        except zeroconf.Error as e:
            logging.exception(e)
            raise ZeroconfException() from e

    async def stop(self):
        await self._manager.unregister_all_services()
        logging.debug(f"Unregistered services.")

    async def __aenter__(self):
        await self.start()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
        return not isinstance(exc_val, ZeroconfException)
