"""
CompanionGames
Copyright (C) 2024 thiccaxe

Partially Generated with AI

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

import win32api
import win32con
from pycaw.pycaw import AudioUtilities

from input_backend import InputBackend

# win32api.mouse_event flags
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004


class WindowsInput(InputBackend):

    def __init__(self, loop: asyncio.AbstractEventLoop):
        super().__init__(loop)
        

    async def __aenter__(self):
        logging.debug("WindowsInput: entering context")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logging.debug("WindowsInput: exiting context")

    async def key_press(self, character: str):
        vk_and_shift = win32api.VkKeyScan(character)
        vk = vk_and_shift & 0xFF
        shift = (vk_and_shift >> 8) & 0xFF

        needs_shift = shift & 0x01
        if needs_shift:
            win32api.keybd_event(win32con.VK_SHIFT, 0, 0, 0)

        win32api.keybd_event(vk, 0, 0, 0)
        win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)

        if needs_shift:
            win32api.keybd_event(win32con.VK_SHIFT, 0, win32con.KEYEVENTF_KEYUP, 0)

    async def delete_char(self):
        win32api.keybd_event(win32con.VK_BACK, 0, 0, 0)
        win32api.keybd_event(win32con.VK_BACK, 0, win32con.KEYEVENTF_KEYUP, 0)

    async def lmb_down(self):
        win32api.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)

    async def lmb_up(self):
        win32api.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)

    async def deltas(self, dx: int = 0, dy: int = 0):
        win32api.mouse_event(MOUSEEVENTF_MOVE, dx, dy, 0, 0)

    async def volume_toggle_mute(self):
        device = AudioUtilities.GetSpeakers()
        volume = device.EndpointVolume
        volume.SetMute(not volume.GetMute(), None)
    
    async def volume_up(self):
        device = AudioUtilities.GetSpeakers()
        volume = device.EndpointVolume
        volume.VolumeStepUp(None)

    async def volume_down(self):
        device = AudioUtilities.GetSpeakers()
        volume = device.EndpointVolume
        volume.VolumeStepDown(None)