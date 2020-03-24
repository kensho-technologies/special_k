# Copyright 2020-present Kensho Technologies, LLC.
"""Various utilities"""
import contextlib
from datetime import datetime
from errno import ENOENT
import hashlib
import hmac
import logging
import os
import shutil
import string
import tarfile
import tempfile
from typing import Dict
from uuid import uuid4

import gpg
import numpy as np
import pandas as pd
from voluptuous import All, Length, validate
from voluptuous.error import ValueInvalid

from .exceptions import IntegrityError, SerializationError


try:
    from pip._internal.operations import freeze
except ImportError:  # pip < 10.0
    try:
        from pip.operations import freeze
    except ImportError:  # pip not installed
        freeze = None


HASH_FUNCTION = hashlib.sha256
START_OF_HISTORY = datetime.fromtimestamp(0)
NON_EMPTY_STRING = All(str, Length(min=1))

logger = logging.getLogger(__name__)


def _hash_list_of_numpy_arrays(list_of_arrays, hash_function):
    """Compute a unique hash for a list of numpy arrays"""
    if not (isinstance(list_of_arrays, list) and isinstance(list_of_arrays[0], np.ndarray)):
        raise TypeError("Expected list of numpy arrays. Found {}".format(type(list_of_arrays)))
    hsh = hash_function()
    for array in list_of_arrays:
        hsh.update(array.tostring())
    return hsh.hexdigest()


def _safe_hash(array_or_list_of_arrays, hash_function):
    """Hash a numpy array or a list of numpy arrays."""
    if isinstance(array_or_list_of_arrays, np.ndarray):
        return hash_function(array_or_list_of_arrays.tostring()).hexdigest()
    elif isinstance(array_or_list_of_arrays, list):
        return _hash_list_of_numpy_arrays(array_or_list_of_arrays, hash_function)
    else:
        raise TypeError(
            "Expected list of numpy arrays. Found {}".format(type(array_or_list_of_arrays))
        )


def hmac_hash(filepath, key):
    """Hash a file with HMAC"""
    hash_hmac = hmac.new(bytearray(key, "utf-8"), digestmod=HASH_FUNCTION)
    with open(filepath, "rb") as buff:
        for chunk in iter(lambda: buff.read(4096), b""):
            hash_hmac.update(chunk)
    return hash_hmac.hexdigest()


def calculate_stream_hmac(stream, hmac_key):
    """Calculate a stream's HMAC code with the given key."""
    stream.seek(0)
    hash_hmac = hmac.new(bytearray(hmac_key, "utf-8"), digestmod=HASH_FUNCTION)
    while True:
        buf = stream.read(4096)
        if not buf:
            break
        hash_hmac.update(buf)

    return hash_hmac.hexdigest()


# # # #
# PUBLIC API
# # # #


def validate_stream_hmac(stream, stream_name, hmac_key, expected_hmac_code):
    """Validate that the stream's HMAC code matches the expected code."""
    actual_hmac_code = calculate_stream_hmac(stream, hmac_key)

    expected_hmac = bytearray(expected_hmac_code, "utf-8")
    actual_hmac = bytearray(actual_hmac_code, "utf-8")
    if not hmac.compare_digest(expected_hmac, actual_hmac):
        raise IntegrityError(
            'For the stream named "{}", the calculated HMAC code did not match '
            "the expected HMAC code! This could mean that the file was corrupted "
            "during storage or transit, but may also signal malicious "
            "intent.".format(stream_name)
        )


@contextlib.contextmanager
def get_temporary_directory():
    """Context manager that makes a temporary directory that can be used for testing purposes."""
    test_dir = tempfile.mkdtemp()
    # Ensure the temporary directory exists and is visible to all processes
    # by fsyncing both the temporary directory itself, and its parent directory.
    # Without this code, that would not be guaranteed, and might make for flaky performance.
    fd = os.open(test_dir, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(os.path.dirname(test_dir), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    yield test_dir
    shutil.rmtree(test_dir, ignore_errors=True)


@contextlib.contextmanager
def get_gpg_homedir_and_context(passphrase, algorithm="rsa2048"):
    """Get a temporary home directory, gpg key and fingerprint for testing signing logic

    Args:
        passphrase: to use for signing key
        algorithm: cryptographic algorithm. CHANGE THIS WITH GREAT CARE

    Yields:
        gpg_home_dir, new_key (for signing), fingerprint (of signing key)
    """
    with get_temporary_directory() as gpg_home_dir:
        # gpg_home_dir is now fsync'ed
        with gpg.Context(
            home_dir=gpg_home_dir,
            armor=True,
            offline=True,
            pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
        ) as ctx:
            new_key = ctx.create_key(
                "test@example.com", algorithm=algorithm, sign=True, passphrase=passphrase
            )
            fingerprint = new_key.fpr
            yield gpg_home_dir, new_key, fingerprint


def _get_subkey_latest_expiration(key) -> datetime:
    """Get the expiration date for the last expiring subkey of a gpgme key"""
    expiry_timestamps = [subkey.expires for subkey in key.subkeys]
    # an expiration of 0 is code for no expiration, so we treat that case separately
    if any(expiry_timestamp == 0 for expiry_timestamp in expiry_timestamps):
        latest_expiration = 0
    else:
        latest_expiration = max(expiry_timestamps)
    return datetime.fromtimestamp(latest_expiration)


def get_key_expirations_for_gpg_context(ctx: gpg.Context) -> Dict[str, datetime]:
    """Get the keys and expirations that live in a gpg context"""
    # WARNING: we need to use system time, not utc time because gpg uses system time
    now = datetime.now()
    fpr_to_expiry = {key.fpr: _get_subkey_latest_expiration(key) for key in ctx.keylist()}
    for fpr, expiry in fpr_to_expiry.items():
        # timestamp of the unix epoch is code for no expiration
        never_expires = expiry == START_OF_HISTORY
        expired = bool(ctx.get_key(fpr).expired)
        expiry_in_the_past = (expiry < now) and not never_expires
        expiration_date_str = expiry.strftime("%y-%m-%d")

        if never_expires and expired:
            raise AssertionError(
                "This should never happen. Key with fingerprint {} has no expiration date but is "
                "marked as expired".format(fpr)
            )
        if expired and not expiry_in_the_past:
            raise AssertionError(
                "This should never happen. Key with fingerprint {} is marked as expired but the "
                "expiration is {}, which is in the future".format(fpr, expiration_date_str)
            )
        if not expired and expiry_in_the_past:
            raise AssertionError(
                "This should never happen. Key with fingerprint {} is marked as not expired but "
                "the expiration date is {} which is in the past".format(fpr, expiration_date_str)
            )
    return fpr_to_expiry


def hash_train_and_val_data(x_train, y_train, x_val, y_val):
    """Make a dict of the hashes of the training and val data."""
    hash_function = hashlib.sha256
    return {
        "x_train": _safe_hash(x_train, hash_function),
        "y_train": _safe_hash(y_train, hash_function),
        "x_val": _safe_hash(x_val, hash_function),
        "y_val": _safe_hash(y_val, hash_function),
    }


@validate(param_value=str)
def filename_safe_string(param_value):
    """Ensure the provided parameter value is a filename-safe string, with no special characters."""
    chars = frozenset(param_value)
    allowed_chars = frozenset(string.ascii_letters + string.digits + "-_.")

    prohibited_chars = chars - allowed_chars
    if prohibited_chars:
        raise ValueInvalid(
            "Found prohibited characters in filename-safe string parameter {}".format(param_value)
        )
    return param_value


def open_readonly_tarball_file(tar_file, member_name):
    """Return a context manager that is essentially open() but for files inside a tarball.

    Args:
        tar_file: TarFile, the tarball whose files to open
        member_name: string, the path of the tarball member file to open, given in form relative
                     to the root of the tarball archive (e.g. "dirA/dirB/foo.txt")

    Returns:
        context manager with the same contract as the "open()" builtin

    Raises:
        SerializationError, if no such member exists or the member is not a file
    """
    try:
        tarinfo = tar_file.getmember(member_name)
    except KeyError:
        raise SerializationError(
            'The tarball does not contain a member with name "{}", '
            "members are: {}".format(member_name, tar_file.getnames())
        )

    if not tarinfo.isfile():
        raise SerializationError(
            "The tarball has a member with the given name, but it is not "
            "a file-like object: {}".format(member_name)
        )

    return contextlib.closing(tar_file.extractfile(tarinfo))


def consume_stream_into_tarball(tar_file, member_name, stream):
    """Add the stream to the tarball, at the location and with the name specified in member_name.

    N.B: Upon calling this function, the caller relinquishes ownership of the stream.
         The stream is consumed and closed within this function; it is illegal for the caller
         to attempt any further operations on the stream after calling this function.

    Args:
        tar_file: TarFile, the tarball where to save the stream
        member_name: string, the path of the tarball member file to create, given in form relative
                     to the root of the tarball archive (e.g. "dirA/dirB/foo.txt")
        stream: file-like object to be written into the tarball, then closed
    """
    tarinfo = tarfile.TarInfo(name=member_name)

    # The TarInfo requires that we explicitly tell it how long the stream is.
    # The best way to do that is to seek to the end of the stream, and then ask for the position.
    stream.seek(0, os.SEEK_END)
    tarinfo.size = stream.tell()
    stream.seek(0)  # Rewind the stream to its start.

    tar_file.addfile(tarinfo, fileobj=stream)
    stream.close()


def get_model_directory_name(tar_file):
    """Return the directory where the model is stored from the given tarball.

    Even though the tarball is known to only contain a single directory, the name of
    that directory is not specified or known ahead of time. This function asserts
    the existence of only a single directory in the tarball, and then returns its name.

    Args:
        tar_file: TarFile, the tarball containing the model

    Returns:
        string, the name of the directory where the model is stored
    """
    directory_names = [tar_info.name for tar_info in tar_file.getmembers() if tar_info.isdir()]
    if len(directory_names) != 1:
        raise SerializationError(
            "Expected a tarball with exactly one directory inside, but that "
            "was not the case: {}".format(directory_names)
        )
    else:
        return directory_names[0]


def make_model_directory(tar_file):
    """Make a directory with a randomly-generated name in the tarball, then return its name."""
    # Randomly generate the model directory name, to make extracting models from tarballs
    # less likely to accidentally produce overlapping model directories.
    model_directory_name = "model_" + str(uuid4()).replace("-", "")

    # Create the directory in the tarball.
    tar_directory = tarfile.TarInfo(name=model_directory_name)
    tar_directory.type = tarfile.DIRTYPE
    tar_file.addfile(tar_directory)

    return model_directory_name


def safe_pd_read_msgpack(file_path):
    """Load msgpack file into a dataframe and throw if file doesn't exist. Fixed in pandas 0.23."""
    if os.path.exists(file_path):
        return pd.read_msgpack(file_path)
    else:
        raise IOError(ENOENT, "File not found!", file_path)


def get_installed_packages():
    """Get a list of installed packages"""
    if freeze is None:
        return []
    else:
        return list(freeze.freeze())
