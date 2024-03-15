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
import dataclasses
import uuid
from typing import Optional

import websockets


@dataclasses.dataclass
class TypingSession:
    tsid: uuid.UUID
    meta: dict
    hdpid: str  # hashed device pairing id


class ServerData:

    def __init__(self):
        self.connected_clients: dict[str, asyncio.Protocol] = dict()
        self.connected_website: Optional[websockets.WebSocketServerProtocol] = None
        self.typing_sessions: dict[str, TypingSession] = dict()

        self.shutdown_event = asyncio.Event()
