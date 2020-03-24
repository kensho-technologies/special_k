# Copyright 2020-present Kensho Technologies, LLC.
import glob
import json
import os
import string


_KEYNAME_TO_FINGERPRINT_FILE = "keyname-to-fingerprint.json"
_TRUSTDB_FILE = "trustdb.txt"
ALLOWED_FINGERPRINT_CHARACTERS = set(string.ascii_uppercase + string.digits)


def get_trusted_keys_dir():
    """Get the trusted keys directory from an environment variable"""
    trusted_keys_dir = os.environ.get("SERIALIZATION_TRUSTED_KEYS_DIR")
    if trusted_keys_dir is None:
        raise ValueError(
            "Could not find trusted pub key directory. "
            "You must set environment variable `SERIALIZATION_TRUSTED_KEYS_DIR`"
        )
    return trusted_keys_dir


def _verify_trusted_keys_dir(trusted_keys_dir):
    """Verify that a trusted keys directory has the proper contents"""
    files = glob.glob(os.path.join(trusted_keys_dir, "*"))
    has_pub_key = any(filepath.endswith(".pub.asc") for filepath in files)
    if not has_pub_key:
        raise ValueError("No public keys found in directory {}, {}".format(trusted_keys_dir, files))
    has_trustdb = any(os.path.split(filepath)[-1] == _TRUSTDB_FILE for filepath in files)
    if not has_trustdb:
        raise ValueError("No `{}` found in directory {}".format(_TRUSTDB_FILE, trusted_keys_dir))
    has_fingerprint_json = any(
        os.path.split(filepath)[-1] == _KEYNAME_TO_FINGERPRINT_FILE for filepath in files
    )
    if not has_fingerprint_json:
        raise ValueError(
            "No file `{}` found in {}.".format(_KEYNAME_TO_FINGERPRINT_FILE, trusted_keys_dir)
        )


def _is_fingerprint_valid(fingerprint):
    """Validate that a fingerprint is in the right format"""
    if len(fingerprint) != 40:
        return False
    elif set(fingerprint).difference(ALLOWED_FINGERPRINT_CHARACTERS):
        return False
    else:
        return True


def _validate_keyname_to_fingerprint_item(keyname, fingerprint):
    """Validate that a keyname and fingerprint are well-formed."""
    if not isinstance(keyname, str):
        raise TypeError("Found keyname of type {} instead of `str`".format(type(keyname)))
    if len(keyname) == 0:
        raise ValueError("Found empty keyname")
    if not isinstance(fingerprint, str):
        raise TypeError("Found fingerprint of type {} instead of `str`".format(type(fingerprint)))
    if not _is_fingerprint_valid(fingerprint):
        raise ValueError(
            "Found incorrect fingerprint format {}. Fingerprint should be a "
            "40 character string of uppercase letters and numbers. "
            "You can find the fingerprint with `gpg2 --list-keys` with the "
            "appropriate `--homedir` specified".format(fingerprint)
        )


def get_keyname_to_fingerprint():
    """Get a map of pub key filename to fingerprint"""
    trusted_keys_dir = get_trusted_keys_dir()
    filepath = os.path.join(trusted_keys_dir, _KEYNAME_TO_FINGERPRINT_FILE)
    with open(filepath, "r") as fi:
        keyname_to_fingerprint = json.load(fi)
    for keyname, fingerprint in keyname_to_fingerprint.items():
        _validate_keyname_to_fingerprint_item(keyname, fingerprint)
    return keyname_to_fingerprint


def get_trusted_pub_keys():
    """Get the trusted pub key files"""
    trusted_keys_dir = get_trusted_keys_dir()
    _verify_trusted_keys_dir(trusted_keys_dir)
    pub_key_files = glob.glob(os.path.join(trusted_keys_dir, "*.pub.asc"))
    return frozenset(os.path.basename(filepath) for filepath in pub_key_files)
