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

from server_data import ServerData

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

    def set_websocket_server(self, websocket_server): self._websocket_server = websocket_server

    def set_companion_server(self, companion_server): self._companion_server = companion_server
