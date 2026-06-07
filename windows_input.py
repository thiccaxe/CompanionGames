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
import ctypes
import logging

import win32api
import win32con
from pycaw.pycaw import AudioUtilities

from input_backend import InputBackend

# win32api.mouse_event flags
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004

# SendInput Unicode helpers
_PUL = ctypes.POINTER(ctypes.c_ulong)
_INPUT_KEYBOARD = 1
_KEYEVENTF_UNICODE = 0x0004
_KEYEVENTF_KEYUP = 0x0002


class _KeybdInput(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", _PUL),
    ]


class _MouseInput(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", _PUL),
    ]


class _InputUnion(ctypes.Union):
    _fields_ = [("ki", _KeybdInput), ("mi", _MouseInput)]


class _Input(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("ii", _InputUnion)]


def _send_unicode_key(wchar: int, key_up: bool = False) -> None:
    flags = _KEYEVENTF_UNICODE | (_KEYEVENTF_KEYUP if key_up else 0)
    extra = ctypes.c_ulong(0)
    inp = _Input(
        type=_INPUT_KEYBOARD,
        ii=_InputUnion(
            ki=_KeybdInput(wVk=0, wScan=wchar, dwFlags=flags, time=0, dwExtraInfo=ctypes.pointer(extra))
        ),
    )
    ctypes.windll.user32.SendInput(1, ctypes.pointer(inp), ctypes.sizeof(inp))


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

        if vk_and_shift == -1:
            cp = ord(character)
            if cp > 0xFFFF:
                # Emoji / outside-BMP: send as UTF-16 surrogate pair
                cp -= 0x10000
                high = 0xD800 | (cp >> 10)
                low = 0xDC00 | (cp & 0x3FF)
                _send_unicode_key(high)
                _send_unicode_key(low)
                _send_unicode_key(low, key_up=True)
                _send_unicode_key(high, key_up=True)
            else:
                _send_unicode_key(cp)
                _send_unicode_key(cp, key_up=True)
            return

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