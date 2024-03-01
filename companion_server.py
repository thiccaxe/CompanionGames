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
import binascii
import dataclasses
import hashlib
import inspect
import logging
import secrets
from asyncio import Server

import cryptography.exceptions
import tomlkit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from random import randbytes
from srptools import SRPContext, SRPServerSession, constants

from typing import Optional, List, Union, Tuple
from pyatv.protocols.companion.protocol import (
    FrameType,
)

from fruit.hkdf import hkdf_expand
from server_data import ServerData
from fruit.chacha20 import Chacha20Cipher
from fruit.hap_tlv8 import write_tlv, read_tlv, TlvValue, ErrorCode
from fruit import opack

COMPANION_AUTH_FRAMES = (
    FrameType.PS_Start,
    FrameType.PS_Next,
    FrameType.PV_Start,
    FrameType.PV_Next,
)

COMPANION_OPACK_FRAMES = (
    FrameType.E_OPACK,
    FrameType.U_OPACK,
    FrameType.P_OPACK,
)


@dataclasses.dataclass()
class CompanionAuthVerifySession:
    """
    cleaned up after "setup" procedure is complete, replaced with encrypted session
    """
    apid: bytes
    server_lt_private_key: Ed25519PrivateKey
    server_lt_public_key: Ed25519PublicKey
    hdpid: Optional[str]
    psid: Optional[str]
    server_private_key: X25519PrivateKey
    server_public_key: X25519PublicKey
    device_public_key: Optional[X25519PublicKey]
    shared_key: Optional[bytes]
    session_key: Optional[bytes]
    chacha: Optional[Chacha20Cipher]  # session key chacha

    def process_device_public_key(self, device_public_key: bytes) -> None:
        self.device_public_key = X25519PublicKey.from_public_bytes(device_public_key)
        self.shared_key = self.server_private_key.exchange(self.device_public_key)

        self.session_key = hkdf_expand(
            "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", self.shared_key
        )

    def create_m1_signature(self):
        device_info = (self.server_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
                       + self.apid
                       + self.device_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))
        return self.server_lt_private_key.sign(device_info)

    def encrypt(self, data, nonce):
        if self.chacha is None:
            self.chacha = Chacha20Cipher(self.session_key, self.session_key)
        return self.chacha.encrypt(data, nonce)

    def decrypt(self, data, nonce):
        if self.chacha is None:
            self.chacha = Chacha20Cipher(self.session_key, self.session_key)
        return self.chacha.decrypt(data, nonce)

    def verify_m3_signature(self, dpid, pairing, signature):
        self.hdpid = pairing["hdpid"]
        self.psid = pairing["psid"]
        device_info = self.device_public_key.public_bytes_raw() + dpid + self.server_public_key.public_bytes_raw()
        try:
            ios_ltpk = Ed25519PublicKey.from_public_bytes(binascii.unhexlify(pairing["ltpk"]))
            return ios_ltpk.verify(bytes(signature), bytes(device_info)) is None
        except cryptography.exceptions.InvalidKey as e:
            logging.exception(e)
            return False
        except cryptography.exceptions.InvalidSignature as e:
            logging.error("invalid signature")
            return False

    def convert(self):
        return CompanionAuthEncryptedSession(
            self.hdpid,
            Chacha20Cipher(
                hkdf_expand("", "ServerEncrypt-main", self.shared_key),
                hkdf_expand("", "ClientEncrypt-main", self.shared_key),
                nonce_length=12,
            ),
        )

    @staticmethod
    def create(apid: bytes, server_lt_private_key_bytes: bytes):
        server_lt_private_key = Ed25519PrivateKey.from_private_bytes(server_lt_private_key_bytes)
        verify_private_key = X25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
        return CompanionAuthVerifySession(
            apid, server_lt_private_key, server_lt_private_key.public_key(),
            None, None,
            verify_private_key, verify_private_key.public_key(),
            None, None, None, None
        )


@dataclasses.dataclass()
class CompanionAuthEncryptedSession:
    """
    used during regular encrypted use
    goal: store as less data as possible
    """
    hdpid: str
    chacha: Chacha20Cipher  # chacha based on keys derived from shared_key

    def decrypt(self, frame_type, frame_data) -> bytes:
        header = bytes([frame_type.value]) + len(frame_data).to_bytes(3, byteorder="big")
        return self.chacha.decrypt(bytes(frame_data), aad=header)

    def encrypt(self, frame_type: FrameType, frame_data: bytes) -> bytes:
        header = bytes([frame_type.value]) + (len(frame_data) + 16).to_bytes(3, byteorder="big")
        # add 16 for "auth tag"
        return self.chacha.encrypt(frame_data, aad=header)


@dataclasses.dataclass
class CompanionAuthSetupSession:
    """
    cleaned up after "setup" procedure is complete
    """
    apid: bytes
    psid: str
    salt: bytes
    srp_session: SRPServerSession
    device_x: Optional[bytes]
    server_x: Optional[bytes]
    session_chacha: Optional[Chacha20Cipher]
    encryption_chacha: Optional[Chacha20Cipher]
    hdpid: Optional[bytes]
    device_lt_public_key: Optional[Ed25519PublicKey]
    server_lt_private_key: Optional[Ed25519PrivateKey]
    server_lt_public_key: Optional[Ed25519PublicKey]

    @staticmethod
    def create(apid: bytes, psid: str, pin: str, server_lt_private_key_bytes: bytes):
        context = SRPContext(
            "Pair-Setup",
            str(pin),
            prime=constants.PRIME_3072,
            generator=constants.PRIME_3072_GEN,
            hash_func=hashlib.sha512,
            bits_salt=128,
        )
        username, verifier, salt = context.get_user_data_triplet()

        context_server = SRPContext(
            username,
            prime=constants.PRIME_3072,
            generator=constants.PRIME_3072_GEN,
            hash_func=hashlib.sha512,
            bits_salt=128,
        )

        session = SRPServerSession(
            context_server, verifier, binascii.hexlify(server_lt_private_key_bytes).decode()
        )
        server_lt_private_key = Ed25519PrivateKey.from_private_bytes(server_lt_private_key_bytes)

        return CompanionAuthSetupSession(
            apid=apid,
            psid=psid,
            salt=salt,
            srp_session=session,
            device_x=None,
            server_x=None,
            session_chacha=None,
            encryption_chacha=None,
            hdpid=None,
            device_lt_public_key=None,
            server_lt_private_key=server_lt_private_key,
            server_lt_public_key=server_lt_private_key.public_key(),
        )

    def derive_from_session_key(self):
        self.server_x = hkdf_expand(
            "Pair-Setup-Accessory-Sign-Salt",
            "Pair-Setup-Accessory-Sign-Info",
            binascii.unhexlify(self.srp_session.key),
        )
        self.device_x = hkdf_expand(
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
            binascii.unhexlify(self.srp_session.key),
        )
        session_key = hkdf_expand(
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            binascii.unhexlify(self.srp_session.key),
        )

        self.session_chacha = Chacha20Cipher(session_key, session_key)
        self.encryption_chacha = Chacha20Cipher(
            hkdf_expand("", "ServerEncrypt-main", binascii.unhexlify(self.srp_session.key)),
            hkdf_expand("", "ClientEncrypt-main", binascii.unhexlify(self.srp_session.key)),
        )

    def encrypt(self, data, nonce):
        if self.session_chacha is None:
            self.derive_from_session_key()
        return self.session_chacha.encrypt(data, nonce)

    def decrypt(self, data, nonce):
        if self.session_chacha is None:
            self.derive_from_session_key()
        return self.session_chacha.decrypt(data, nonce)

    def verify_m5_request(self, dpid: bytes, device_lt_public_key_bytes, signature: bytes):
        device_info = self.device_x + dpid + device_lt_public_key_bytes
        self.device_lt_public_key = Ed25519PublicKey.from_public_bytes(device_lt_public_key_bytes)
        try:
            return self.device_lt_public_key.verify(signature, device_info) is None
        except cryptography.exceptions.InvalidSignature as e:
            return False

    def create_m5_signature(self):
        server_info = self.server_x + self.apid + self.server_lt_public_key.public_bytes_raw()
        return self.server_lt_private_key.sign(server_info)

    def convert(self):
        return CompanionAuthEncryptedSession(
            binascii.hexlify(self.hdpid).decode("utf-8"),
            self.encryption_chacha,
        )


class CompanionSession:

    async def handle_frame(self, frame: dict) -> Optional[dict]:
        return None


class CompanionDummySession(CompanionSession):
    def __init__(self, config, secrets):
        super(CompanionDummySession, self).__init__()
        self._config = config
        self._secrets = secrets
        self._packet_handlers = {
            "_systemInfo": self._handle_system_info_packet,
            # "_sessionStart": self._handle_session_start_packet,
            # "_sessionStop": self._handle_session_stop_packet,
            # "FetchAttentionState": self._handle_fetch_attention_state,
            # "FetchSiriRemoteInfo": self._handle_fetch_siri_remote_info,
            # "_mcc": self._handle_mcc,
            # "_touchStart": self._handle_touch_start,
            # "_touchStop": self._handle_touch_stop,
            # "_hidT": self._handle_hid_touchpad,
            # "_hidC": self._handle_click,
        }

    async def handle_frame(self, frame):
        response: dict = None
        packet_nonce = 0
        if "_x" in frame:
            packet_nonce = frame["_x"]

        if "_i" in frame:
            packet_type = frame["_i"]
            if packet_type in self._packet_handlers:
                packet_handler = self._packet_handlers[packet_type]
                if inspect.iscoroutinefunction(packet_handler):
                    response = await packet_handler(frame)
                else:
                    response = packet_handler(frame)

        response = response if response else {}
        response.setdefault("_x", packet_nonce)
        response.setdefault("_t", 3)
        response.setdefault("_c", {})



        return response

    def _handle_system_info_packet(self, frame):
        response = {
            "_c": {
                "_pubID": self._config["server"]["mac"],
                "_mRtID": self._config["server"]["id"],
                "_mrID": self._config["server"]["id"],
                "_dCapF": 1,
                "_bf": 1920,
                "_lP": int(self._config["server"]["companion_port"]),
                "_i": "de179cfc3a9e",
                "_clFl": 128,
                "model": "AppleTV5,3",
                'name': self._config["server"]["name"],
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

class CompanionConnectionProtocol(asyncio.Protocol):
    _peername: Tuple[bytes, int] = None

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
        self._auth_session: Optional[Union[
            CompanionAuthVerifySession,
            CompanionAuthSetupSession,
            CompanionAuthEncryptedSession
        ]] = None
        self._session: Optional[CompanionSession] = None
        self._auth_handlers = {
            "setup_M1": self._process_setup_m1,
            "setup_M3": self._process_setup_m3,
            "setup_M5": self._process_setup_m5,
            "verify_M1": self._process_verify_m1,
            "verify_M3": self._process_verify_m3,
        }

    def connection_made(self, transport):
        self._peername = transport.get_extra_info('peername')
        logging.debug(f"{self._peername} connection made")
        self._transport = transport
        self._buffer_read_task = asyncio.ensure_future(self._process_buffer())
        self._loop.create_task(self.on_shutdown())

    def data_received(self, data):
        self._buffer += data
        logging.debug(f"{self._peername} received data")
        self._buffer_write_event.set()

    async def _process_buffer(self):
        while not self._data.shutdown_event.is_set() and not self._connection_closed_event.is_set():
            try:
                await self._buffer_write_event.wait()  # buffer has been written to
                data: bytearray = self._buffer.copy()  # copy buffer
                self._buffer.clear()  # clear
                self._buffer_write_event.clear()  # reset event
                data_len = len(data)
                logging.debug(f"{self._peername} handling data with length {data_len}: {binascii.hexlify(data)}")
                offset = 0
                while (data_len - offset) >= 4:  # Minimum size: 1 byte frame type + 3 byte length
                    # generate a random id for this frame
                    _id = int.from_bytes(randbytes(3), "big")
                    # byte 1 to byte 4 is length; add 4 bytes for header.
                    payload_length = 4 + int.from_bytes(data[(offset + 1):(offset + 4)], byteorder="big")
                    logging.debug(f"{offset=} / {data_len=} / {payload_length=}")
                    if payload_length > (data_len - offset):
                        logging.debug(f"{self._peername} remaining data too small for packet")
                        break
                    # frame type is the first byte
                    frame_type = FrameType(data[0])
                    logging.debug(f"{self._peername} {frame_type=}")
                    # frame data doesn't include packet type, just length and the data
                    frame_data = data[(offset + 4):(offset + payload_length)]
                    await self._handle_frame(frame_type, frame_data)
                    offset += payload_length
                    logging.debug(f"{self._peername} {_id=} {offset=}")
                    if offset == data_len:
                        break
                    logging.debug(f"{self._peername} {_id=} finished handling data")
                # at this point, copy the unread data in the copied buffer to the start of real buffer.
                # not ideal if data is filling up faster than we can process, but we shouldn't run into that :)
                self._buffer[0:0] = data[offset:]
            except asyncio.CancelledError:
                break

        logging.debug(f"{self._peername} stopped processing buffer")

    async def _handle_frame(self, frame_type, frame_data):
        if frame_type in COMPANION_AUTH_FRAMES:
            await self._handle_auth_frame(frame_type, frame_data)
        elif frame_type in COMPANION_OPACK_FRAMES:
            await self._handle_play_frame(frame_type, frame_data)

    async def _handle_play_frame(self, frame_type, frame_data):
        logging.debug(f"{self._peername} handling play frame")
        if self._session is None or self._auth_session is None or not isinstance(self._auth_session,
                                                                                 CompanionAuthEncryptedSession):
            logging.debug(f"{self._peername} not ready for this packet")
            return

        if len(frame_data) == 0:
            return

        try:

            unencrypted_frame_data = self._auth_session.decrypt(frame_type, frame_data)
            frame: dict = opack.unpack(unencrypted_frame_data)[0]
            logging.debug(f"{self._peername} {frame=}")

        except Exception as e:
            logging.exception(e)
            logging.warning("Could not handle frame")
            return

        # pawn it off to session handler
        response_frame = await self._session.handle_frame(frame)
        if response_frame is not None:
            await self._send_opack(frame_type, response_frame)

    async def _handle_auth_frame(self, frame_type, frame_data):
        logging.debug(f"{self._peername} handling auth frame")
        try:
            frame: dict = opack.unpack(frame_data)[0]
            logging.debug(f"{self._peername} {frame=}")
            if "_pd" not in frame:
                logging.warning(f"{self._peername} bad auth frame (opack)")
            pairing_data = read_tlv(frame["_pd"])
            logging.debug(f"{self._peername} {pairing_data=}")
            sequence_number = int.from_bytes(pairing_data[TlvValue.SeqNo], byteorder="little")
            auth_type = "verify" if frame_type in (FrameType.PV_Start, FrameType.PV_Next) else "setup"
            logging.debug(
                f"{self._peername} responding to {auth_type} auth frame, containing data for M{sequence_number}")
            await self._auth_handlers[f"{auth_type}_M{sequence_number}"](pairing_data)
        # except OPackException as e:
        #     logging.exception(e)
        #     logging.error(f"{self._peername} could not parse auth frame (opack)")
        except KeyError as e:
            logging.exception(e)
            logging.error(f"{self._peername} could not parse auth frame (no handler)")
        except Exception as e:
            logging.exception(e)

    async def _send_opack(self, frame_type: FrameType, obj: object) -> None:
        await self._send_frame(frame_type, opack.pack(obj))

    async def _send_frame(self, frame_type: FrameType, frame_data: bytes):
        if self._transport is None:
            logging.warning(f"{self._peername} Tried to send frame with no connection {frame_type=} {frame_data=}")
        if self._auth_session is None:
            logging.warning(f"{self._peername} Tried to send frame with no active session {frame_type=} {frame_data=}")
            return

        if isinstance(self._auth_session, CompanionAuthEncryptedSession):
            frame_data = self._auth_session.encrypt(frame_type, frame_data)
            # decrypt data

        header = bytes([frame_type.value]) + len(frame_data).to_bytes(3, byteorder="big")

        self._transport.write(header + frame_data)

    async def _process_setup_m1(self, pairing_data):
        if self._auth_session is not None:
            self._auth_session = None
        self._auth_session = CompanionAuthSetupSession.create(
            self._config["server"]["id"].encode(),
            "002c38c4-d08d-4c99-908e-98bfc2921531",
            "1234",
            binascii.unhexlify(self._secrets["server"]["private_key"]),
        )
        logging.debug(self._auth_session)
        tlv = write_tlv(
            {
                TlvValue.SeqNo: b"\x02",
                TlvValue.Salt: binascii.unhexlify(self._auth_session.salt),
                TlvValue.PublicKey: binascii.unhexlify(self._auth_session.srp_session.public),
                27: b"\x01",
            }
        )
        data = opack.pack({
            "_pd": tlv
        })

        await self._send_frame(FrameType.PS_Next, data)

    async def _process_setup_m3(self, pairing_data):
        if (self._auth_session is None) or (not isinstance(self._auth_session, CompanionAuthSetupSession)):
            logging.error("no auth session")
            return  # TODO error

        if not self._verify_psid_is_valid(self._auth_session.psid):
            self._auth_session = None
            logging.error("bad psid")
            return  # TODO error

        logging.debug(f"{self._peername} processing public key")

        device_srp_publickey = binascii.hexlify(pairing_data[TlvValue.PublicKey]).decode()
        self._auth_session.srp_session.process(device_srp_publickey, self._auth_session.salt)

        logging.debug(f"{self._peername} processed srp data")

        tlv = {
            TlvValue.Error: bytes([ErrorCode.Authentication]),
            TlvValue.SeqNo: b"\x04",
        }
        if self._auth_session.srp_session.verify_proof(binascii.hexlify(pairing_data[TlvValue.Proof])):
            proof = binascii.unhexlify(self._auth_session.srp_session.key_proof_hash)
            tlv = {TlvValue.Proof: proof, TlvValue.SeqNo: b"\x04"}

        data = opack.pack({
            "_pd": write_tlv(tlv)
        })

        await self._send_frame(FrameType.PS_Next, data)

    async def _process_setup_m5(self, pairing_data):
        if self._auth_session is None or not isinstance(self._auth_session, CompanionAuthSetupSession):
            return  # TODO error

        if not self._verify_psid_is_valid(self._auth_session.psid):
            logging.debug(f"{self._peername} psid {self._auth_session.psid} is no longer valid")
            self._auth_session = None
            return  # TODO error

        try:
            decrypted_tlv_bytes = self._auth_session.decrypt(bytes(pairing_data[TlvValue.EncryptedData]),
                                                             "PS-Msg05".encode())
        except Exception as e:
            logging.exception(e)
            logging.debug(f"{self._peername} Invalid M5 encrypted tlv")
            self._auth_session = None
            return  # TODO error

        decrypted_tlv = read_tlv(decrypted_tlv_bytes)
        logging.debug(f"{self._peername} decrypted tlv {decrypted_tlv}")

        if not self._auth_session.verify_m5_request(
                decrypted_tlv[TlvValue.Identifier],
                decrypted_tlv[TlvValue.PublicKey],
                decrypted_tlv[TlvValue.Signature],
        ):
            logging.debug(f"{self._peername} Invalid M5 signature")
            self._auth_session = None
            return  # TODO error

        self._auth_session.hdpid = self.compute_hdpid(decrypted_tlv[TlvValue.Identifier])

        logging.debug(f"{self._peername} valid M5 signature")

        signature = self._auth_session.create_m5_signature()

        logging.debug(f"{self._peername} created M5 response signature")

        extra = {
            "accountID": self._auth_session.apid.decode("utf-8"),
            "model": "AppleTV5,3",
            "wifiMAC": b"@" + binascii.unhexlify(str(self._config["server"]["mac"]).replace(":", "")),
            "name": "NotUxPlay",
            "mac": b"@" + binascii.unhexlify(str(self._config["server"]["mac"]).replace(":", "")),
        }

        unencrypted_tlv = {
            TlvValue.Identifier: self._auth_session.apid,
            TlvValue.PublicKey: self._auth_session.server_lt_public_key.public_bytes_raw(),
            TlvValue.Signature: signature,
            17: opack.pack(extra),
        }
        logging.debug(f"{self._peername} {unencrypted_tlv=}")
        encrypted = self._auth_session.encrypt(write_tlv(unencrypted_tlv),
                                               nonce="PS-Msg06".encode())  # last necesary step
        tlv = {
            TlvValue.SeqNo: b"\x06", TlvValue.EncryptedData: encrypted
        }
        logging.debug(f"{self._peername} {tlv=}")

        data = opack.pack({
            "_pd": write_tlv(tlv)
        })

        await self._send_frame(FrameType.PS_Next, data)

        self._save_pairing()

        self._auth_session = self._auth_session.convert()
        self._session = CompanionDummySession(self._config, self._secrets)

    def _verify_psid_is_valid(self, psid):
        pairings = self._secrets["pairings"]
        for _psid in pairings:
            if _psid == psid:
                return bool(pairings[_psid]["allow_pairing"])

        return False

    def compute_hdpid(self, dpid: bytes):
        _hash = hashlib.sha256()
        _hash.update(dpid)
        _hash.update(binascii.unhexlify(self._secrets["server"]["dpid_salt"]))
        return _hash.digest()

    def _save_pairing(self):
        pairing = tomlkit.table()
        hdpid = binascii.hexlify(self._auth_session.hdpid).decode("utf-8")
        ltpk = binascii.hexlify(self._auth_session.device_lt_public_key.public_bytes_raw()).decode("utf-8")
        pairing.add("hdpid", hdpid)
        pairing.add("psid", self._auth_session.psid)
        pairing.add("ltpk", ltpk)
        logging.debug(f"{self._peername} {pairing=}")
        self._secrets["clients"][hdpid] = pairing

    async def _verify_flow_authentication_error(self, discard_session: bool = True, error_code: bytes = b"\x02"):
        await self._send_opack(FrameType.PV_Next, {
            "_pd": write_tlv({
                TlvValue.SeqNo: b"\x04",
                TlvValue.Error: error_code,
            })
        })
        if discard_session:
            self._auth_session = None

    async def _process_verify_m1(self, pairing_data):
        # delete old auth session, if it exists
        self._auth_session = None
        # Check if pairing data is valid
        if TlvValue.PublicKey not in pairing_data:
            logging.error(f"{self._peername} bad verify m1 frame, no client public key")
            await self._verify_flow_authentication_error(discard_session=False)  # already done
            return
        client_public_key_bytes = pairing_data[TlvValue.PublicKey]
        self._auth_session = None
        self._auth_session = CompanionAuthVerifySession.create(
            self._config["server"]["id"].encode(), binascii.unhexlify(self._secrets["server"]["private_key"]),
        )

        logging.debug(self._auth_session)

        try:
            self._auth_session.process_device_public_key(bytes(client_public_key_bytes))
        except cryptography.exceptions.InvalidKey as e:
            logging.exception(e)
            logging.error(f"{self._peername} could not generate shared key")
            await self._verify_flow_authentication_error()
            return

        try:
            signature = self._auth_session.create_m1_signature()
            sub_tlv = write_tlv({
                TlvValue.Identifier: self._auth_session.apid,
                TlvValue.Signature: signature
            })
            encrypted_sub_tlv = self._auth_session.encrypt(sub_tlv, "PV-Msg02".encode())
        except Exception as e:
            logging.exception(e)
            logging.error(f"{self._peername} could not generate device info signature")
            await self._verify_flow_authentication_error()
            return

        tlv = write_tlv(
            {
                TlvValue.SeqNo: b"\x02",
                TlvValue.PublicKey: self._auth_session.server_public_key.public_bytes_raw(),
                TlvValue.EncryptedData: encrypted_sub_tlv,
            }
        )
        data = opack.pack({
            "_pd": tlv
        })

        await self._send_frame(FrameType.PV_Next, data)

    async def _process_verify_m3(self, pairing_data):
        if (self._auth_session is None) or (not isinstance(self._auth_session, CompanionAuthVerifySession)):
            logging.error(f"no auth session; auth session type {type(self._auth_session)}")
            await self._verify_flow_authentication_error()
            return

        if TlvValue.EncryptedData not in pairing_data:
            logging.error(f"{self._peername} bad verify m3 frame, no encrypted data")
            await self._verify_flow_authentication_error()
            return

        try:
            decrypted_tlv_bytes = self._auth_session.decrypt(bytes(pairing_data[TlvValue.EncryptedData]),
                                                             "PV-Msg03".encode())
        except Exception as e:
            logging.exception(e)
            logging.debug(f"{self._peername} Invalid M3 encrypted tlv")
            await self._verify_flow_authentication_error()
            return

        decrypted_tlv = read_tlv(decrypted_tlv_bytes)
        logging.debug(f"{self._peername} decrypted tlv: {decrypted_tlv}")

        if TlvValue.Identifier not in decrypted_tlv:
            logging.debug(f"{self._peername} no identifier in m3 decrypted tlv")
            await self._verify_flow_authentication_error()
            return

        if TlvValue.Signature not in decrypted_tlv:
            logging.debug(f"{self._peername} no signature in m3 decrypted tlv")
            await self._verify_flow_authentication_error()
            return

        hdpid = self.compute_hdpid(decrypted_tlv[TlvValue.Identifier])
        device_pairing = self._get_device_pairing(hdpid)

        logging.debug(f"{self._peername} potentially using {device_pairing=}")

        if device_pairing is None:
            logging.debug(f"{self._peername} device has not been paired, giving up.")
            await self._verify_flow_authentication_error()
            return

        if not self._client_pairing_session_exists(device_pairing):
            logging.debug(f"{self._peername} bad pairing session, giving up.")
            await self._verify_flow_authentication_error()
            return

        if not self._client_pairing_session_can_connect(device_pairing):
            logging.debug(f"{self._peername} client cannot connect with given pairing session.")
            self._connection_closed_event.set() # not sure if best solution
            return

        logging.debug(f"{self._peername} session key {binascii.hexlify(self._auth_session.session_key)}")

        if not self._auth_session.verify_m3_signature(decrypted_tlv[TlvValue.Identifier], device_pairing,
                                                      decrypted_tlv[TlvValue.Signature]):
            logging.debug(f"{self._peername} bad device signature")
            await self._verify_flow_authentication_error()
            return

        await self._send_opack(FrameType.PV_Next, {
            "_pd": write_tlv({
                TlvValue.SeqNo: b"\x04",
            }),
        })

        self._auth_session = self._auth_session.convert()
        self._session = CompanionDummySession(self._config, self._secrets)

    def _get_device_pairing(self, hdpid: bytes) -> Optional[dict]:
        hdpid_str = binascii.hexlify(hdpid).decode('utf-8')
        if hdpid_str in self._secrets["clients"]:
            return self._secrets["clients"][hdpid_str]

        return None

    def _client_pairing_session_exists(self, device_pairing: dict) -> bool:
        if "psid" not in device_pairing:
            logging.debug(f"No psid in device pairing")
            return False

        psid = device_pairing["psid"]

        if psid not in self._secrets["pairings"]:
            logging.debug(f"{psid=} does not exist")
            return False

        return True

    def _client_pairing_session_can_connect(self, device_pairing: dict) -> bool:
        """
        precondition: psid exists in db
        """
        psid = device_pairing["psid"]
        pairing = self._secrets["pairings"][psid]

        if "allow_connections" not in pairing:
            logging.warning(f"pairing {psid=} is malformed")
            return False

        return bool(pairing["allow_connections"])

    def connection_lost(self, error):
        logging.debug(f"{self._peername} connection lost")
        self._connection_closed_event.set()

    async def on_shutdown(self):
        logging.debug(f"{self._peername} awaiting shutdown")
        await asyncio.wait([
            self._loop.create_task(self._data.shutdown_event.wait()),
            self._loop.create_task(self._connection_closed_event.wait()),
        ], return_when=asyncio.FIRST_COMPLETED)
        if self._transport:
            self._buffer_read_task.cancel()
            if not self._connection_closed_event.is_set():
                self.connection_lost(None)
            logging.debug(f"{self._peername} shutting down transport")
            self._transport.close()
            logging.debug(f"{self._peername} connection cleaned up")

        del self._buffer  # in case?


class CompanionServer:
    def __init__(self, config, secrets, loop: asyncio.AbstractEventLoop, data, manager):
        self._loop = loop
        self._config = config
        self._secrets = secrets
        self._data = data
        self._server: Optional[Union[List[Server], Server]] = None
        self._manager = manager
        self._manager.set_companion_server(self)

    def _protocol_factory(self):
        proto = CompanionConnectionProtocol(
            self._loop, self._config, self._secrets, self._data
        )
        return proto

    async def __aenter__(self):
        try:
            self._server = await self._loop.create_server(
                self._protocol_factory,
                None, int(self._config["server"]["companion_port"]), start_serving=False)
            logging.debug("created companion server")
        except asyncio.CancelledError as e:
            logging.exception(e)
        await self._server.start_serving()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._server is not None:
            self._data.shutdown_event.set()
            if isinstance(self._server, list):
                for server in self._server:
                    server.close()
                await asyncio.wait([
                    asyncio.create_task(server.wait_closed()) for server in self._server
                ], return_when=asyncio.ALL_COMPLETED)
            else:
                self._server.close()
                await self._server.wait_closed()
            logging.debug("closed companion server")
