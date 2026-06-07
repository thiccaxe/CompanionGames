"""
CompanionGames
Copyright (C) 2026 thiccaxe

Generated with AI

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


class InputBackend:

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    async def __aenter__(self):
        logging.debug("InputBackend stub: entering context")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logging.debug("InputBackend stub: exiting context")

    async def key_press(self, character: str):
        logging.debug(f"InputBackend stub: key_press({character!r})")

    async def delete_char(self):
        logging.debug("InputBackend stub: delete_char()")

    async def lmb_down(self):
        logging.debug("InputBackend stub: lmb_down()")

    async def lmb_up(self):
        logging.debug("InputBackend stub: lmb_up()")

    async def deltas(self, dx: int = 0, dy: int = 0):
        logging.debug(f"InputBackend stub: deltas({dx=}, {dy=})")

    async def volume_up(self):
        logging.debug(f"InputBackend stub: Volume up")

    async def volume_down(self):
        logging.debug(f"InputBackend stub: Volume down")

    async def volume_toggle_mute(self):
        logging.debug(f"InputBackend stub: Volume toggle mute")
