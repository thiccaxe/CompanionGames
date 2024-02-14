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
"""Companion server authentication code."""

from abc import ABC, abstractmethod
import binascii
from collections import namedtuple
import hashlib
import logging

_print = print
from rich import print
from rich.traceback import install

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
import cryptography.exceptions

from srptools import SRPContext, SRPServerSession, constants

from pyatv.auth.hap_srp import hkdf_expand
from pyatv.auth.hap_tlv8 import ErrorCode, TlvValue, read_tlv, write_tlv
from pyatv.protocols.companion.connection import FrameType
from pyatv.support import chacha20, log_binary, opack

_LOGGER = logging.getLogger(__name__)

PIN_CODE = 1111
SERVER_IDENTIFIER = "5D737FD3-5538-427E-A57B-A32FC7DF4A7F"
PRIVATE_KEY = 32 * b"\xEE"
PUBLIC_ID = "69:9C:57:33:6D:16"
BLUETOOTH_ADDRESS = "AD:97:7C:BA:A3:9F"

ServerKeys = namedtuple("ServerKeys", "sign auth auth_pub verify verify_pub")

paired = {
}

install()


def generate_keys(seed):
    """Generate server encryption keys from seed."""
    signing_key = Ed25519PrivateKey.from_private_bytes(seed)
    verify_private = X25519PrivateKey.from_private_bytes(seed)
    return ServerKeys(
        sign=signing_key,
        auth=signing_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        auth_pub=signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ),
        verify=verify_private,
        verify_pub=verify_private.public_key(),
    )


def new_server_session(keys, pin):
    """Create SRP server session."""
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
        context_server, verifier, binascii.hexlify(keys.auth).decode()
    )

    return session, salt


class CompanionServerAuth(ABC):
    """Server-side implementation of Companion authentication."""

    def __init__(self, device_name, allow_pair = True, unique_id=SERVER_IDENTIFIER, pin=PIN_CODE):
        """Initialize a new instance if CompanionServerAuth."""
        self.device_name = device_name
        self.unique_id = unique_id.encode()
        self.input_key = None
        self.output_key = None
        self.keys = generate_keys(PRIVATE_KEY)
        self.pin = pin
        self.session, self.salt = new_server_session(self.keys, pin)
        self.allow_pair = allow_pair

    def handle_auth_frame(self, frame_type, data):
        """Handle incoming auth message."""
        _LOGGER.debug("Received auth frame: type=%s, data=%s", frame_type, data)
        pairing_data = read_tlv(data["_pd"])
        print(pairing_data)
        seqno = int.from_bytes(pairing_data[TlvValue.SeqNo], byteorder="little")

        suffix = (
            "verify"
            if frame_type in [FrameType.PV_Start, FrameType.PV_Next]
            else "setup"
        )
        print(f"_m{seqno}_{suffix}")
        getattr(self, f"_m{seqno}_{suffix}")(pairing_data)

    def _m1_verify(self, pairing_data):
        server_pub_key = self.keys.verify_pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.client_pub_key = pairing_data[TlvValue.PublicKey]

        shared_key = self.keys.verify.exchange(
            X25519PublicKey.from_public_bytes(self.client_pub_key)
        )

        self.shared_key = shared_key

        session_key = hkdf_expand(
            "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared_key
        )

        self.session_key = session_key

        info = server_pub_key + self.unique_id + self.client_pub_key
        signature = self.keys.sign.sign(info)

        tlv = write_tlv(
            {TlvValue.Identifier: self.unique_id, TlvValue.Signature: signature}
        )
        print("AUTH - unencrypted sending", {TlvValue.Identifier: self.unique_id, TlvValue.Signature: signature})

        chacha = chacha20.Chacha20Cipher(session_key, session_key)
        encrypted = chacha.encrypt(tlv, nonce="PV-Msg02".encode())

        tlv = write_tlv(
            {
                TlvValue.SeqNo: b"\x02",
                TlvValue.PublicKey: server_pub_key,
                TlvValue.EncryptedData: encrypted,
            }
        )
        print("AUTH - sending", {
            TlvValue.SeqNo: b"\x02",
            TlvValue.PublicKey: server_pub_key,
            TlvValue.EncryptedData: encrypted,
        })

        self.output_key = hkdf_expand("", "ServerEncrypt-main", shared_key)
        self.input_key = hkdf_expand("", "ClientEncrypt-main", shared_key)

        log_binary(_LOGGER, "Keys", Output=self.output_key, Input=self.input_key)

        self.send_to_client(FrameType.PV_Next, {"_pd": tlv})

    def _m3_verify(self, pairing_data):
        tlv = {TlvValue.SeqNo: b"\x04", }

        chacha = chacha20.Chacha20Cipher(self.session_key, self.session_key)
        out = read_tlv(chacha.decrypt(pairing_data[TlvValue.EncryptedData], nonce="PV-Msg03".encode()))
        print(out)
        print("out contains device identifier", TlvValue.Identifier in out)
        print(out[TlvValue.Identifier], paired)
        if TlvValue.Identifier not in out or out[TlvValue.Identifier] not in paired:
            print("device has not been paired, giving up.")
            tlv[TlvValue.Error] = "\x02"
            self.send_to_client(
                FrameType.PV_Next, {"_pd": write_tlv(tlv)}
            )
            return
        ios_ident = out[TlvValue.Identifier]
        ios_ltpk = binascii.unhexlify(paired[ios_ident])
        public_key = Ed25519PublicKey.from_public_bytes(ios_ltpk)
        print(f"{public_key=}")
        ios_device_info = self.client_pub_key + ios_ident + self.keys.verify_pub.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        print("DEVICE_INFO", binascii.hexlify(ios_device_info))

        signature_status = False
        try:
            signature_status = public_key.verify(out[TlvValue.Signature], ios_device_info) is None
        except cryptography.exceptions.InvalidSignature as e:
            print(e)
        print("signature_status", signature_status)

        if signature_status is not True:
            tlv[TlvValue.Error] = b'\x02'

        print("AUTH - sending", tlv)
        self.send_to_client(
            FrameType.PV_Next, {"_pd": write_tlv(tlv)}
        )
        self.enable_encryption(self.output_key, self.input_key)

    def _m1_setup(self, pairing_data):
        if self.allow_pair:
            tlv = write_tlv(
                {
                    TlvValue.SeqNo: b"\x02",
                    TlvValue.Salt: binascii.unhexlify(self.salt),
                    TlvValue.PublicKey: binascii.unhexlify(self.session.public),
                    27: b"\x01",
                }
            )
        else:
            tlv = write_tlv(
                {
                    TlvValue.SeqNo: b"\x02",
                    TlvValue.Error: b"\x06",
                }
            )
        print("AUTH - sending", tlv)
        self.send_to_client(FrameType.PS_Next, {"_pd": tlv, "_pwTy": 1})

    def _m3_setup(self, pairing_data):
        pubkey = binascii.hexlify(pairing_data[TlvValue.PublicKey]).decode()
        self.session.process(pubkey, self.salt)

        if self.session.verify_proof(binascii.hexlify(pairing_data[TlvValue.Proof])):
            proof = binascii.unhexlify(self.session.key_proof_hash)
            tlv = {TlvValue.Proof: proof, TlvValue.SeqNo: b"\x04"}
        else:
            tlv = {
                TlvValue.Error: bytes([ErrorCode.Authentication]),
                TlvValue.SeqNo: b"\x04",
            }
        print("AUTH - sending", tlv)
        print("session key:", binascii.unhexlify(self.session.key))

        self.send_to_client(FrameType.PS_Next, {"_pd": write_tlv(tlv)})

    def _m5_setup(self, pairing_data):
        print("initial session key: ", self.session.key)
        acc_device_x = hkdf_expand(
            "Pair-Setup-Accessory-Sign-Salt",
            "Pair-Setup-Accessory-Sign-Info",
            binascii.unhexlify(self.session.key),
        )
        ios_device_x = hkdf_expand(
            "Pair-Setup-Controller-Sign-Salt",
            "Pair-Setup-Controller-Sign-Info",
            binascii.unhexlify(self.session.key),
        )

        session_key = hkdf_expand(
            "Pair-Setup-Encrypt-Salt",
            "Pair-Setup-Encrypt-Info",
            binascii.unhexlify(self.session.key),
        )

        chacha = chacha20.Chacha20Cipher(session_key, session_key)
        decrypted_tlv_bytes = chacha.decrypt(
            pairing_data[TlvValue.EncryptedData], nonce="PS-Msg05".encode()
        )
        print("decrypted_tlv_bytes", decrypted_tlv_bytes)
        decrypted_tlv = read_tlv(decrypted_tlv_bytes)

        print("m5 decrypted tlv:", decrypted_tlv)
        print("m5 dec re-bytes:", write_tlv(decrypted_tlv))

        if TlvValue.Name in decrypted_tlv:
            print("m5 decrypted name:", opack.unpack(decrypted_tlv[TlvValue.Name]))
        else:
            pass

        print("ios_device_x", ios_device_x)
        print(binascii.hexlify(decrypted_tlv[TlvValue.Identifier]))
        print(binascii.hexlify(decrypted_tlv[TlvValue.PublicKey]))
        device_info = ios_device_x + decrypted_tlv[TlvValue.Identifier] + decrypted_tlv[TlvValue.PublicKey]
        print("device_info", device_info)
        public_key = Ed25519PublicKey.from_public_bytes(decrypted_tlv[TlvValue.PublicKey])
        print("made public key", public_key)
        print(public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
        signature_status = -1
        try:
            signature_status = public_key.verify(decrypted_tlv[TlvValue.Signature], device_info) is None
        except cryptography.exceptions.InvalidSignature as e:
            print(e)
        print("signature_status", signature_status)
        other = {
            "accountID": SERVER_IDENTIFIER,
            "model": "AppleTV5,3",
            "wifiMAC": b"@" + binascii.unhexlify(PUBLIC_ID.replace(":","")),
            "name": "NotUxPlay",
            "mac": b"@" + binascii.unhexlify(PUBLIC_ID.replace(":","")),
        }


        device_info = acc_device_x + self.unique_id + self.keys.auth_pub
        signature = self.keys.sign.sign(device_info)

        tlv = {
            TlvValue.Identifier: self.unique_id,
            TlvValue.PublicKey: self.keys.auth_pub,
            TlvValue.Signature: signature,
            17: opack.pack(other),
        }
        print("AUTH - sending encrypted data", tlv)

        tlv = write_tlv(tlv)

        chacha = chacha20.Chacha20Cipher(session_key, session_key)
        encrypted = chacha.encrypt(tlv, nonce="PS-Msg06".encode())
        print("AUTH - sending", {TlvValue.SeqNo: b"\x06", TlvValue.EncryptedData: encrypted})
        tlv = write_tlv({TlvValue.SeqNo: b"\x06", TlvValue.EncryptedData: encrypted})

        self.send_to_client(FrameType.PS_Next, {"_pd": tlv})
        self.has_paired()

    @abstractmethod
    def send_to_client(self, frame_type: FrameType, data: object) -> None:
        """Send data to client device (iOS)."""

    @abstractmethod
    def enable_encryption(self, output_key: bytes, input_key: bytes) -> None:
        """Enable encryption with the specified keys."""

    @staticmethod
    def has_paired():
        """Call when a client has paired."""
