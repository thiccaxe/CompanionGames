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

import binascii
import logging
import uuid

import cryptography.exceptions
from voluptuous import Schema, Required, Optional, Any, All, Range, Length
import voluptuous.error
import aiofiles
import tomlkit
import tomlkit.exceptions
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ConfigurationLoadError(Exception): pass


class Config:
    config: tomlkit.TOMLDocument
    secrets: tomlkit.TOMLDocument
    secrets_opened: bool = False
    config_opened: bool = False

    def __init__(self, config_location: Path, secrets_location: Path):
        self.config_location = config_location
        self.secrets_location = secrets_location

        self.config_schema = Schema({
            Required('server'): {
                Required('name'): All(str, Length(min=1)),
                Required('id'): All(lambda _uuid: uuid.UUID(_uuid, version=4)),
                Required('companion_port'): All(int, Range(min=0, max=65535)),
                Required('websocket_port'): All(int, Range(min=0, max=65535)),
                Required('mac'): All(str, Length(17)),
            }
        })
        self.secrets_schema = Schema({
            Required('server'): {
                Required('private_key'): All(str, Length(64), self.key_validator),
                Required('websocket_secret'): All(str, Length(min=32, max=256)),
                Required('dpid_salt'): All(str, Length(64), self.key_validator),
            },
            Required('clients'): Any(None, dict),
            Required('pairings'): Any(None, dict),
        })

    @staticmethod
    def key_validator(private_key: str) -> str:
        try:
            _private_key = binascii.unhexlify(private_key)
        except binascii.Error as e:
            logging.exception(e)
            raise voluptuous.error.Invalid(message="Invalid key.") from e
        return private_key

    async def initialize(self):
        try:
            async with aiofiles.open(self.config_location, 'r') as config_file:
                file_data = await config_file.read()
                self.config = tomlkit.parse(file_data)
                logging.debug("Loaded Configuration without toml format error")
                logging.debug("Validating against Schema.")
                self.config_schema(self.config.unwrap())
                self.config_opened = True
                logging.debug("Validated against Schema.")
        except FileNotFoundError as e:
            logging.exception(e)
            logging.warning(
                f"Could not find {self.config_location}. Copy from .example/config.toml to {self.config_location}")
            raise ConfigurationLoadError() from e
        except IOError as e:
            logging.exception(e)
            logging.warning(f"Could not open file {self.config_location}")
            raise ConfigurationLoadError() from e
        except tomlkit.exceptions.ParseError as e:
            logging.exception(e)
            logging.warning(f"Configuration in {self.config_location} is invalid")
            raise ConfigurationLoadError() from e
        except voluptuous.error.MultipleInvalid as e:
            logging.exception(e)
            logging.warning(f"Configuration in {self.config_location} does not match expected format")
            logging.warning(f"Issue configuration item: {e.path}")
            raise ConfigurationLoadError() from e

        logging.debug(f"Loaded Configuration")

        try:
            async with aiofiles.open(self.secrets_location, 'r') as secrets_file:
                file_data = await secrets_file.read()
                self.secrets = tomlkit.parse(file_data)
                logging.debug("Loaded Secrets without toml format error")
                logging.debug("Validating against Schema.")
                self.secrets_schema(self.secrets.unwrap())
                logging.debug("Validated against Schema.")
                self.secrets_opened = True
        except FileNotFoundError as e:
            logging.exception(e)
            logging.warning(
                f"Could not find {self.secrets_location}. Copy from .example/secrets.toml to {self.secrets_location}")
            raise ConfigurationLoadError() from e
        except IOError as e:
            logging.exception(e)
            logging.warning(f"Could not open file {self.secrets_location}")
            raise ConfigurationLoadError() from e
        except tomlkit.exceptions.ParseError as e:
            logging.exception(e)
            logging.warning(f"Secrets in {self.secrets_location} is invalid")
            raise ConfigurationLoadError() from e
        except voluptuous.error.MultipleInvalid as e:
            logging.exception(e)
            logging.warning(f"Secrets in {self.secrets_location} does not match expected format")
            logging.warning(f"Issue configuration item: {e.path}")
            raise ConfigurationLoadError() from e

        logging.debug(f"Loaded Secrets")
        logging.info(f"Configuration loaded.")

    async def close(self):
        if self.config_opened is True:
            async with aiofiles.open(self.config_location, 'w') as config_file:
                await config_file.write(tomlkit.dumps(self.config))
            logging.debug("Config file saved to disk.")

        if self.secrets_opened is True:
            async with aiofiles.open(self.secrets_location, 'w') as secrets_file:
                await secrets_file.write(tomlkit.dumps(self.secrets))
            logging.debug("Secrets file saved to disk.")
        logging.info(f"Configuration Saved.")
