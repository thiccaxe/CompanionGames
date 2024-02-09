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
"""
This file includes a significant portion of pyatv - see ATTRIBUTION.txt
"""



import asyncio
import binascii
import time
from random import randbytes
from socket import inet_aton
from typing import Optional

import cryptography
from pyatv.protocols.companion.connection import (
    AUTH_TAG_LENGTH,
)
from pyatv.protocols.companion.protocol import (
    FrameType,
)
from pyatv.protocols.companion.server_auth import CompanionServerAuth
from pyatv.support import (
    chacha20,
    opack,
)
from rich import print
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf, AsyncServiceInfo

SERVER_NAME = "NotUxPlay"
BLUETOOTH_ADDRESS = "DA:97:7C:BA:A3:7B"
PUBLIC_ID = "69:9C:57:22:6D:92"
AIRPLAY_IDENTIFIER = "4D797FD3-3538-427E-A47B-A32FC6CFDDDD"
SERVER_IDENTIFIER = "4D797FD3-3538-427E-A47B-A32FC6CFDDDD"
ADDRESS = "192.168.1.35"
SERVER_ADDRESSES = [inet_aton(ADDRESS),]
SERVER_PORT = 34689
SERVER_APPLETV_VERSION="523.1.2"
SERVER_APPLETV_MODEL="AppleTV5,3"

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
    def __init__(self):
        super().__init__(
            SERVER_NAME,
            SERVER_IDENTIFIER,
            1234
        )
        self.transport = None
        self.chacha: Optional[chacha20.Chacha20Cipher] = None
        self.packet_handlers = {
            "_systemInfo": self.handle_system_info_packet,
            "_sessionStart": self.handle_session_start_packet,
            "_sessionStop": self.handle_session_stop_packet,
            "FetchAttentionState": self.handle_fetch_attention_state,
            "FetchSiriRemoteInfo": self.handle_fetch_siri_remote_info,
            "_mcc": self.handle_mcc,
            "_touchStart": self.handle_touch_start,
            "_touchStop": self.handle_touch_stop,
            "_hidT": self.handle_hid_touchpad,
        }
        self.services = {}
        self.touch = None

        
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))
        self.transport = transport

    def connection_lost(self, error):
        print('Connection lost from {}'.format(self.peername))

    def data_received(self, data):
        data_len = len(data)
        _id = int.from_bytes(randbytes(3), "big")
        print(_id, 'Data received: {!r}'.format(binascii.hexlify(data)))
        offset = 0
        while True:
            payload_length = 4 + int.from_bytes(data[(offset+1):(offset+4)], byteorder="big")
            print("Offset / Data Length / Payload Length", offset, data_len, payload_length)
            if (payload_length > (data_len - offset)):
                print(_id, "break, data too small")
                break

            frame_type = FrameType(data[0])
            print(f"{frame_type=}")
            frame_data = data[(offset+4):(offset+payload_length)]

            self.handle_frame(frame_type, frame_data)
            offset += payload_length
            print(_id, offset)
            if (offset) == data_len:
                break
        print(_id, "finished handling data.")

        



    def handle_frame(self, frame_type, frame_data):
        if frame_type in COMPANION_AUTH_FRAMES:
            print("auth frame!")
            frame = opack.unpack(frame_data)
            print(frame)
            try:
                self.handle_auth_frame(frame_type, frame[0])
            except Exception as e:
                print(e)
                print("failed to handle auth frame")
        else:
            try:
                if frame_type in COMPANION_OPACK_FRAMES:
                    print("opack frame; decode")
                    self.handle_play_frame(frame_type, frame_data)
            except Exception as e:
                print(type(e), e)
                print("error")

    def handle_play_frame(self, frame_type, frame_data):
        if self.chacha and len(frame_data) > 0: # data is encrypted
            try:
                header = bytes([frame_type.value]) + len(frame_data).to_bytes(3, byteorder="big")
                temp = self.chacha.decrypt(frame_data, aad=header)
                frame_data = temp
            except cryptography.exceptions.InvalidTag as e:
                print(e)
                print("not encrypted maybe?")
        
        packet = opack.unpack(frame_data)[0]
        print(packet)
        response: dict = None
        packet_nonce = 0
        if "_x" in packet:
            packet_nonce = packet["_x"]

        if "_i" in packet:
            packet_type = packet["_i"]
            if packet_type in self.packet_handlers:
                response = self.packet_handlers[packet_type](packet)
        
        response = response if response else {}
        response.setdefault("_x", packet_nonce)
        response.setdefault("_t", 3)
        response.setdefault("_c", {})

        self.send_to_client(frame_type, response)


    
    def handle_system_info_packet(self, packet):
        try:
            print(opack.unpack(packet["_c"]["_siriInfo"]["sharedDataProtoBuf"]))
        except Exception as e: print(e)
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
                '_stA': ['com.apple.callservicesd.CompanionLinkManager', 'com.apple.bluetooth.remote', 'com.apple.workflow.remotewidgets', 'com.apple.coreduet.sync', 'com.apple.devicediscoveryui.rapportwake', 'com.apple.biomesyncd.rapport', 'com.apple.SeymourSession', 'com.apple.LiveAudio', 'com.apple.tvremoteservices', 'com.apple.wifivelocityd.rapportWake', 'com.apple.siri.wakeup', 'com.apple.siri.wakeup', 'com.apple.Seymour', 'com.apple.home.messaging'],

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
        if service_type in self.services:
            return {    
                "_c": {
                    "_sid": self.services[service_type]["sid"]
                }
            }
        server_sid = int.from_bytes(randbytes(4), "big")
        self.services[service_type] = {
            "client_sid": client_sid,
            "server_sid": server_sid,
            "sid": (client_sid << 32) | server_sid,
            "init_time": time.time_ns()
        }
        print("Updated Service", self.services[service_type])
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
            if service_type in self.services:
                del self.services[service_type]
        except KeyError:
            pass
    def handle_fetch_attention_state(self, packet):
        return {
            "_c": {
                "state": 0x03 # Awake
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
                diff_2 = self.services["com.apple.tvremoteservices"]["init_time"]
                print(f"{ns_packet=}, {since_touch_start=}, {diff=}, {diff_2=}, diffdiff={diff-diff_2}")

            except KeyError:
                pass


    def send_bytes_to_client(self, frame_type: FrameType, data: bytes) -> None:
        """Send encoded data to client device (iOS)."""
        if not self.transport:
            print("Tried to send to client, but not connected")
            return

        payload_length = len(data)
        if self.chacha and payload_length > 0:
            payload_length += AUTH_TAG_LENGTH
        header = bytes([frame_type.value]) + payload_length.to_bytes(3, byteorder="big")

        if self.chacha and len(data) > 0:
            data = self.chacha.encrypt(data, aad=header)

        self.transport.write(header + data)

    def send_to_client(self, frame_type: FrameType, data: object) -> None:
        """Send data to client device (iOS)."""
        print(frame_type, data)
        self.send_bytes_to_client(frame_type, opack.pack(data))

    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
        """Enable encryption with the specified keys."""
        self.chacha = chacha20.Chacha20Cipher(output_key, input_key, nonce_length=12)




async def main():
    loop = asyncio.get_running_loop()
    mdns = CompanionZeroconfRegistration()
    
    def create_server():
        try:
            server = CompanionRemoteServer(),
            return server
        except Exception as e:
            print(e)

    server = await loop.create_server(
        lambda: CompanionRemoteServer(),
        '0.0.0.0', 34689)

    
    records = {
        "rpHA": "9948cfb6da55",#
        "rpHN": "cef88e5db6fa",#
        "rpAD": "3b2210518c58", #
        "rpHI": "91756a18d8e5",# 
        "rpMd": SERVER_APPLETV_MODEL,#
        "rpVr": SERVER_APPLETV_VERSION,#
        "rpMac": "2",#
        "rpFl": "0XB6782", #
        "rpBA": BLUETOOTH_ADDRESS,#
        "rpMRtID": SERVER_IDENTIFIER,#
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

    try:
        async with server:
            await server.serve_forever()
    except KeyboardInterrupt:
        await mdns.unregsiter_all_services()
        server.close()
    except asyncio.exceptions.CancelledError:
        await mdns.unregsiter_all_services()

if __name__ == "__main__":
    asyncio.run(main())
