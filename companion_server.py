import asyncio
import binascii
import logging
from asyncio import Server
from random import randbytes
from typing import Optional
from pyatv.protocols.companion.protocol import (
    FrameType,
)

from server_data import ServerData


class CompanionConnectionProtocol(asyncio.Protocol):
    def __init__(self, loop: asyncio.AbstractEventLoop, config, secrets, data: ServerData):
        self._transport: Optional[asyncio.Transport] = None
        self._loop = loop
        self._config = config
        self._secrets = secrets
        self._data = data
        self._buffer = bytearray()
        self._buffer_write_event = asyncio.Event()
        self._buffer_read_task: Optional[asyncio.Future] = None
        self._connection_closed_event = asyncio.Event()

    async def start(self) -> None:
        self._buffer_read_task = asyncio.ensure_future(self._process_buffer())

    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(self.peername))
        self._transport = transport
        self._loop.create_task(self.on_shutdown())

    async def on_shutdown(self):
        print("awaiting shutdown - ", self._data.shutdown_event.is_set())
        await asyncio.wait([
            self._loop.create_task(self._data.shutdown_event.wait()),
            self._loop.create_task(self._connection_closed_event.wait()),
        ], return_when=asyncio.FIRST_COMPLETED)
        if self._transport:
            self.connection_lost(None)
            print("shutting down transport")
            self._transport.close()

    def connection_lost(self, error):
        print('Connection lost from {}'.format(self.peername))
        self._connection_closed_event.set()

    async def _process_buffer(self):
        while not self._data.shutdown_event.is_set() and not self._connection_closed_event.is_set():
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


class CompanionServer:
    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data):
        self._loop = loop
        self._config = config
        self._secrets = secrets
        self._data = data
        self._server: Optional[Server] = None

    def _protocol_factory(self):
        try:
            proxy = CompanionConnectionProtocol(
                self._loop, self._config, self._secrets, self._data
            )
            asyncio.ensure_future(
                proxy.start(),
                loop=self._loop,
            )
        except Exception:
            print("failed to start proxy")
            raise
        return proxy

    async def __aenter__(self):
        logging.debug("aenter")
        try:
            self._server = await self._loop.create_server(
                self._protocol_factory,
                '0.0.0.0', int(self._config["server"]["companion_port"]), start_serving=False)
            logging.debug("Created server")
        except Exception as e:
            logging.exception("e")
        return await self._server.start_serving()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._server is not None:
            self._data.shutdown_event.set()
            self._server.close()
            await self._server.wait_closed()
