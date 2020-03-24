# Copyright 2020-present Kensho Technologies, LLC.
import os

from ..serializers.base_serializers import JoblibIO, JsonIO, MsgPackIO, PickleIO


SERIALIZES_JSON_DICTS = frozenset({JoblibIO, JsonIO, MsgPackIO, PickleIO})
_UNSAFE_KEY_PASSPHRASE = "abc"
FAKE_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_keys")
TESTING_PRIVATE_KEY_FILE = os.path.join(FAKE_KEYS_DIR, "testing.secret.asc")
TESTING_ENVVAR = "UNSAFE_GPG_TESTING_ENABLED"
TRUSTED_DIR_ENVVAR = "SERIALIZATION_TRUSTED_KEYS_DIR"
