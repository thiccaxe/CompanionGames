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
from asyncio import BaseTransport, Transport

"""
This file includes a significant portion of pyatv - see ATTRIBUTION.txt
"""

import asyncio
import binascii
import time
from random import randbytes
from socket import inet_aton
from typing import Optional

import cryptography.exceptions
from pyatv.protocols.companion.connection import (
    AUTH_TAG_LENGTH,
)
from pyatv.protocols.companion.protocol import (
    FrameType,
)
from modified_companion_auth import CompanionServerAuth, SERVER_IDENTIFIER, PUBLIC_ID, BLUETOOTH_ADDRESS, _print
from pyatv.support import (
    chacha20,
    opack,
)
from rich import print
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceInfo
import pyautogui as pag

SERVER_NAME = "Companion Games"

AIRPLAY_IDENTIFIER = SERVER_IDENTIFIER

ADDRESS = "192.168.1.35"
SERVER_ADDRESSES = [inet_aton(ADDRESS), ]
SERVER_PORT = 34689
SERVER_APPLETV_VERSION = "523.1.2"
SERVER_APPLETV_MODEL = "AppleTV5,3"

COMPANION_AUTH_FRAMES = [
    FrameType.PS_Start,
    FrameType.PS_Next,
    FrameType.PV_Start,
    FrameType.PV_Next,
]

COMPANION_OPACK_FRAMES = [
    FrameType.E_OPACK,
    FrameType.U_OPACK,
    FrameType.P_OPACK,
]


async def keyboard_interrupt():
    while True:
        try:
            await asyncio.sleep(1)
        except KeyboardInterrupt:
            raise SystemExit


class CompanionZeroconfRegistration:

    def __init__(self):
        self.aiozc = AsyncZeroconf(ip_version=IPVersion.V4Only)

    async def register_service(self, service: AsyncServiceInfo):
        await self.aiozc.async_register_service(service)

    async def unregister_service(self, service: AsyncServiceInfo):
        await self.aiozc.async_unregister_service(service)

    async def unregsiter_all_services(self):
        await self.aiozc.async_unregister_all_services()


class CompanionRemoteServer(CompanionServerAuth, asyncio.Protocol):
    def __init__(self, shutdown_event: asyncio.Event, loop: asyncio.AbstractEventLoop):
        super().__init__(
            SERVER_NAME,
            True, # allow pairing or not
            SERVER_IDENTIFIER,
            1234
        )
        self.peername = None
        self._transport: Transport = None
        self._chacha: Optional[chacha20.Chacha20Cipher] = None
        self._packet_handlers = {
            "_systemInfo": self.handle_system_info_packet,
            "_sessionStart": self.handle_session_start_packet,
            "_sessionStop": self.handle_session_stop_packet,
            "FetchAttentionState": self.handle_fetch_attention_state,
            "FetchSiriRemoteInfo": self.handle_fetch_siri_remote_info,
            "_mcc": self.handle_mcc,
            "_touchStart": self.handle_touch_start,
            "_touchStop": self.handle_touch_stop,
            "_hidT": self.handle_hid_touchpad,
            "_hidC": self.handle_click,
        }
        self._services = {}
        self._touch = None
        self._shutdown_event = shutdown_event
        self.loop = loop
        self._buffer = bytearray()
        self._buffer_write_event = asyncio.Event()
        self._is_connection_closed = False
        self._buffer_read_task: Optional[asyncio.Future] = None

    async def start(self) -> None:
        self._buffer_read_task = asyncio.ensure_future(self._process_buffer())

    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))
        self._transport = transport
        self.loop.create_task(self.on_shutdown())

    async def on_shutdown(self):
        print("awaiting shutdown - ", self._shutdown_event.is_set())
        await self._shutdown_event.wait()
        if self._transport:
            self.connection_lost(None)
            print("shutting down transport")
            self._transport.close()

    def connection_lost(self, error):
        print('Connection lost from {}'.format(self.peername))
        self._is_connection_closed = True

    async def _process_buffer(self):
        while not self._shutdown_event.is_set() and not self._is_connection_closed:
            try:
                await self._buffer_write_event.wait()
                # buffer has been written to
                # copy buffer
                data: bytearray = self._buffer.copy()
                self._buffer.clear()
                print("state of buffer", self._buffer)
                self._buffer_write_event.clear()
                print("Handling ", binascii.hexlify(data))
                data_len = len(data)
                offset = 0
                while (data_len - offset) >= 4:  # Minimums size: 1 byte frame type + 3 byte length
                    # generate a random id for this frame
                    _id = int.from_bytes(randbytes(3), "big")
                    # byte 1 to byte 4 is length; add 4 bytes for header.
                    payload_length = 4 + int.from_bytes(data[(offset + 1):(offset + 4)], byteorder="big")
                    print(f"{offset=} / {data_len=} / {payload_length=}")
                    if payload_length > (data_len - offset):
                        print(_id, "break, data too small")
                        break
                    # frame type is the first byte
                    frame_type = FrameType(data[0])
                    print(f"{frame_type=}")
                    # frame data doesn't include packet type, just length and the data
                    frame_data = data[(offset + 4):(offset + payload_length)]
                    await self._handle_frame(frame_type, frame_data)
                    offset += payload_length
                    print(_id, offset)
                    if offset == data_len:
                        break
                    print(_id, "finished handling data.")
                # at this point, copy the unread data in the copied buffer to the start of our buffer.
                self._buffer[0:0] = data[offset:]
            except asyncio.CancelledError:
                break

        print("done processing buffer; connection over")
    def data_received(self, data):
        self._buffer += data
        self._buffer_write_event.set()



    async def _handle_frame(self, frame_type, frame_data):
        print("Frame Data: ", frame_data)
        if frame_type in COMPANION_AUTH_FRAMES:
            print("auth frame!")
            frame = opack.unpack(bytes(frame_data))
            try:
                self.handle_auth_frame(frame_type, frame[0])
            except Exception as e:
                print(e)
                print("failed to handle auth frame")
        else:
            try:
                if frame_type in COMPANION_OPACK_FRAMES:
                    print("opack frame; decode")
                    self._handle_play_frame(frame_type, frame_data)
            except Exception as e:
                _print(type(e), e)
                print("error")

    def _handle_play_frame(self, frame_type, frame_data):
        print(binascii.hexlify(frame_data))
        if self._chacha and len(frame_data) > 0:  # data is encrypted
            print("play frame is encrypted")
            try:
                header = bytes([frame_type.value]) + len(frame_data).to_bytes(3, byteorder="big")
                print(f"{header=}")
                temp = self._chacha.decrypt(bytes(frame_data), aad=header)
                print(binascii.hexlify(temp))
                frame_data = temp
            except cryptography.exceptions.InvalidTag as e:
                _print(e)
                print("not encrypted maybe?")

        packet = opack.unpack(frame_data)[0]
        print(packet)
        response: dict = None
        packet_nonce = 0
        if "_x" in packet:
            packet_nonce = packet["_x"]

        if "_i" in packet:
            packet_type = packet["_i"]
            if packet_type in self._packet_handlers:
                response = self._packet_handlers[packet_type](packet)

        response = response if response else {}
        response.setdefault("_x", packet_nonce)
        response.setdefault("_t", 3)
        response.setdefault("_c", {})

        self.send_to_client(frame_type, response)

    def handle_system_info_packet(self, packet):
        try:
            print(opack.unpack(packet["_c"]["_siriInfo"]["sharedDataProtoBuf"]))
        except Exception as e:
            print(e)
        response = {
            "_c": {
                "_pubID": PUBLIC_ID,
                "_mRtID": SERVER_IDENTIFIER,
                "_mrID": SERVER_IDENTIFIER,
                "_dCapF": 1,
                "_bf": 1920,
                "_lP": SERVER_PORT,
                "_i": "de179cfc3a9e",
                "_clFl": 128,
                "model": SERVER_APPLETV_MODEL,
                'name': SERVER_NAME,
                '_dC': 'unknown', '_cf': 512, '_sf': 65536,
                '_stA': ['com.apple.callservicesd.CompanionLinkManager', 'com.apple.bluetooth.remote',
                         'com.apple.workflow.remotewidgets', 'com.apple.coreduet.sync',
                         'com.apple.devicediscoveryui.rapportwake', 'com.apple.biomesyncd.rapport',
                         'com.apple.SeymourSession', 'com.apple.LiveAudio', 'com.apple.tvremoteservices',
                         'com.apple.wifivelocityd.rapportWake', 'com.apple.siri.wakeup', 'com.apple.siri.wakeup',
                         'com.apple.Seymour', 'com.apple.home.messaging'],

            }
        }

        return response

    def handle_mcc(self, packet):
        return {
            "_c": {
                '_mcs': 2
            }
        }

    def handle_session_start_packet(self, packet):
        service_type = packet["_c"]["_srvT"]
        client_sid = packet["_c"]["_sid"]
        if (service_type is None) or (client_sid is None):
            return
        if service_type in self._services:
            return {
                "_c": {
                    "_sid": self._services[service_type]["sid"]
                }
            }
        server_sid = int.from_bytes(randbytes(4), "big")
        self._services[service_type] = {
            "client_sid": client_sid,
            "server_sid": server_sid,
            "sid": (client_sid << 32) | server_sid,
            "init_time": time.time_ns()
        }
        print("Updated Service", self._services[service_type])
        return {
            "_c": {
                "_sid": server_sid
            }
        }

    def handle_session_stop_packet(self, packet):
        try:
            service_type = packet["_c"]["_srvT"]
            client_sid = packet["_c"]["_sid"]
            if service_type is None:
                return
            if service_type in self._services:
                del self._services[service_type]
        except KeyError:
            pass

    def handle_fetch_attention_state(self, packet):
        return {
            "_c": {
                "state": 0x03  # Awake
            }
        }

    def handle_fetch_siri_remote_info(self, packet):
        return {
            '_c': {
                'SiriRemoteInfoKey': b'bplist'
            }
        }

    def handle_touch_start(self, packet):
        try:
            width = packet["_c"]["_width"]
            height = packet["_c"]["_height"]
            self.touch = {
                'start': time.time_ns(),
                'pad': {
                    "width": width,
                    "height": height,
                }
            }
        except KeyError:
            pass
        return {
            "_c": {
                "_i": 1
            }
        }

    def handle_touch_stop(self, packet):
        self.touch = None
        pass

    def handle_hid_touchpad(self, packet):
        if self.touch:
            try:
                ns_packet = packet["_c"]["_ns"]
                current_time_ns = time.time_ns()
                since_touch_start = current_time_ns - self.touch['start']
                diff = ns_packet - since_touch_start
                diff_2 = self._services["com.apple.tvremoteservices"]["init_time"]
                print(f"{ns_packet=}, {since_touch_start=}, {diff=}, {diff_2=}, diffdiff={diff - diff_2}")

            except KeyError:
                pass

    def handle_click(self, packet):
        if self.touch:
            try:
                button_info = packet["_c"]
                print("button info")
                print(button_info["_hBtS"] == 1 and button_info["_hidC"] == 6)
                if button_info["_hBtS"] == 1 and button_info["_hidC"] == 6:
                    print("clicking")
                    pag.leftClick()
            except KeyError:
                pass

    def send_bytes_to_client(self, frame_type: FrameType, data: bytes) -> None:
        """Send encoded data to client device (iOS)."""
        if not self._transport:
            print("Tried to send to client, but not connected")
            return

        payload_length = len(data)
        if self._chacha and payload_length > 0:
            payload_length += AUTH_TAG_LENGTH
        header = bytes([frame_type.value]) + payload_length.to_bytes(3, byteorder="big")

        if self._chacha and len(data) > 0:
            data = self._chacha.encrypt(data, aad=header)

        self._transport.write(header + data)

    def send_to_client(self, frame_type: FrameType, data: object) -> None:
        """Send data to client device (iOS)."""
        print(frame_type, data)
        self.send_bytes_to_client(frame_type, opack.pack(data))

    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
        """Enable encryption with the specified keys."""
        self._chacha = chacha20.Chacha20Cipher(output_key, input_key, nonce_length=12)

    def has_paired(self):
        self._transport.close()  # It's for the best


class Manager:

    def __init__(self) -> None:
        pass

    async def main(self):
        pass


async def main():
    loop = asyncio.get_event_loop()
    mdns = CompanionZeroconfRegistration()

    shutdown_event = asyncio.Event()

    def protocol_factory():
        try:
            proxy = CompanionRemoteServer(
                shutdown_event, loop
            )
            asyncio.ensure_future(
                proxy.start(),
                loop=loop,
            )
        except Exception:
            print("failed to start proxy")
            raise
        return proxy

    server = await loop.create_server(
        protocol_factory,
        '0.0.0.0', 34689, start_serving=False)

    records = {
        "rpHA": "9948cfb6da55",  #
        "rpHN": "cef88e5db6fa",  #
        "rpAD": "3b2210518c58",  #
        "rpHI": "91756a18d8e5",  #
        "rpMd": SERVER_APPLETV_MODEL,  #
        "rpVr": SERVER_APPLETV_VERSION,  #
        "rpMac": "2",  #
        "rpFl": "0XB6782",  #
        "rpBA": BLUETOOTH_ADDRESS,  #
        "rpMRtID": SERVER_IDENTIFIER,  #
    }

    service = AsyncServiceInfo(
        "_companion-link._tcp.local.",
        f"{SERVER_NAME}._companion-link._tcp.local.",
        addresses=SERVER_ADDRESSES,
        port=SERVER_PORT,
        properties=records,
        server=f"{SERVER_NAME}.local."
    )
    await mdns.register_service(service)
    print("MDNS Registered")

    # websocket_server = await serve()
    try:
        await server.start_serving()
        print("Server Started")
        await keyboard_interrupt()
    except asyncio.CancelledError:
        pass
    except KeyboardInterrupt:
        pass

    await mdns.unregsiter_all_services()
    print("MDNS Unregistered -- free to Ctrl+C Spam")
    shutdown_event.set()
    print("Broadcasted Shutdown event")
    await asyncio.sleep(1)
    server.close()

    await server.wait_closed()
    print("Server Stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        datefmt="%Y-%m-%d %H:%M:%S",
        format="%(asctime)s %(levelname)s [%(name)s]: %(message)s",
    )
    asyncio.run(main())
