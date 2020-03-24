# Copyright 2020-present Kensho Technologies, LLC.
import codecs
from datetime import datetime
import logging
import os
import subprocess
import time

import gpg
from voluptuous import Optional, validate

from .check_gpg_keys import get_keyname_to_fingerprint, get_trusted_keys_dir, get_trusted_pub_keys
from .utils import NON_EMPTY_STRING, START_OF_HISTORY, get_key_expirations_for_gpg_context


logger = logging.getLogger(__name__)

# WARNING: DO NOT USE the unsafe key for testing.
# Both the public and private keys are checked into the tests to allow for easy testing
_UNSAFE_KEY_FOR_TESTING_FINGERPRINT = "56BC24E20C87C09D3F8C76A96FD20A3075CFFAF2"


TRUSTED_HASH_ALGORITHMS = frozenset(
    {
        gpg.constants.md.SHA224,
        gpg.constants.md.SHA256,
        gpg.constants.md.SHA384,
        gpg.constants.md.SHA512,
    }
)
DAYS_WARNING_FOR_KEY_EXPIRATION = 30  # Warn 30 days prior to key expiry


def _validate_message(message):
    """Ensure the message is correctly representable by GPG."""
    # GPG seems to like adding a newline to the end of the extracted message,
    # regardless of whether or not the original message contained a newline.
    if not message or not message.endswith(b"\n"):
        raise ValueError(
            "Invalid message supplied. The message must be non-empty and must end "
            "in a newline character, otherwise GPG may not be able to sign and "
            "recover it correctly."
        )


def _get_file_contents_from_trusted_dir_as_binary(relative_path):
    """Return the binary contents of the file at the specified path relative to trusted keys dir."""
    trusted_keys_dir = get_trusted_keys_dir()
    filepath = os.path.join(trusted_keys_dir, relative_path)
    with codecs.open(filepath, "rb") as f:
        return f.read()


def _run_command_with_stdin_input(command_args, stdin_data):
    """Run the provided command, passing the given data to stdin."""
    read_pipe, write_pipe = os.pipe()
    write_pipe_closed = False
    try:
        os.write(write_pipe, stdin_data)
        os.close(write_pipe)
        write_pipe_closed = True

        subprocess.check_call(command_args, stdin=read_pipe)
    finally:
        os.close(read_pipe)
        if not write_pipe_closed:
            os.close(write_pipe)


def _set_up_gpg_env_vars_for_gpg_command(gpg_home_dir, gpg_command_args):
    """Produce a new command arguments that set required GPG env vars before running the command."""
    result = [
        "env",
        "-u",
        "GPG_AGENT_INFO",  # There should not be a GPG agent on the system, unset the env var.
        "GNUPGHOME={}".format(gpg_home_dir),  # Tell GPG where to look for keys and trust info.
    ]
    result.extend(gpg_command_args)
    result.append("--batch")  # Use batch mode so that no interactive commands are used
    return result


def _import_trust_db(gpg_home_dir, trustdb_data):
    """Import the GPG trust database into the given GPG home directory."""
    gpg_command = ["gpg", "--import-ownertrust"]
    final_args = _set_up_gpg_env_vars_for_gpg_command(gpg_home_dir, gpg_command)
    _run_command_with_stdin_input(final_args, trustdb_data)


def _import_public_key(gpg_home_dir, pubkey):
    """Import the given public key into the given GPG home directory."""
    gpg_command = ["gpg", "--import"]
    final_args = _set_up_gpg_env_vars_for_gpg_command(gpg_home_dir, gpg_command)
    _run_command_with_stdin_input(final_args, pubkey)


def _import_secret_key(gpg_home_dir, private_key, passphrase):
    """Import a private key into a gpg home directory"""
    gpg_command = ["gpg", "--import"]
    if passphrase is not None:
        gpg_command.extend(["--passphrase", passphrase])

    final_args = _set_up_gpg_env_vars_for_gpg_command(gpg_home_dir, gpg_command)
    _run_command_with_stdin_input(final_args, private_key)


def _is_testing():
    """Determine whether the testing flag is set."""
    is_testing = os.environ.get("UNSAFE_GPG_TESTING_ENABLED")
    if is_testing is None or is_testing == "0":
        return False
    elif is_testing == "1":  # the only value we will accept
        return True
    else:
        raise ValueError(
            "Unknown value {} encountered for `UNSAFE_GPG_TESTING_ENABLED`."
            "Aborting.".format(is_testing)
        )


def _raise_for_unsafe_key(fingerprint):
    """Raise a RuntimeError if an unsafe key is detected."""
    if fingerprint == _UNSAFE_KEY_FOR_TESTING_FINGERPRINT and not _is_testing():
        raise RuntimeError(
            "This should never happen. Unsafe test-only fingerprint found in "
            "trusted keys. The testing flag is not set. Aborting..."
        )


# ##########
# Public API
# ##########


def get_days_until_expiry(ctx: gpg.Context):
    """Get a dictionary of key fingerprint to days until expiry (can be negative)"""
    fpr_to_expiry = get_key_expirations_for_gpg_context(ctx)
    now = datetime.utcnow()
    fpr_to_days = {}
    for fpr, expiry in fpr_to_expiry.items():
        # timestamp of the unix epoch is code for no expiration
        if expiry == START_OF_HISTORY:
            fpr_to_days[fpr] = float("inf")
        else:
            fpr_to_days[fpr] = float((expiry - now).days)
    return fpr_to_days


def warn_for_key_near_expiry(ctx: gpg.Context):
    """Warn if a key is near expiry"""
    fpr_to_expiry_days = get_days_until_expiry(ctx)

    for fpr, days_to_expiry in fpr_to_expiry_days.items():
        if days_to_expiry < 0:
            logger.warning(
                "Found key with fingerprint {} that expired {} days ago. "
                "Fix now!".format(fpr, abs(days_to_expiry))
            )
        elif 0 <= days_to_expiry <= DAYS_WARNING_FOR_KEY_EXPIRATION:
            logger.warning(
                "Found key with fingerprint {} that expires in {} days. "
                "Fix ASAP!".format(fpr, days_to_expiry)
            )


def import_secret_key(gpg_home_dir, private_key_file, passphrase=None):
    """Import a private key into gpg home directory"""
    with codecs.open(private_key_file, "rb") as f:
        private_key = f.read()
    _import_secret_key(gpg_home_dir, private_key, passphrase)


@validate(gpg_home_dir=NON_EMPTY_STRING)
def add_trusted_keys_to_gpg_home_dir(gpg_home_dir):
    """Add known trusted keys to the given GPG home directory.

    Args:
        gpg_home_dir: string, the directory where GPG should look for keys and trust information.
                      The directory is required to already exist.
    """
    trusted_pub_keys = get_trusted_pub_keys()
    # Import trusted public keys.
    for key_filename, fingerprint in get_keyname_to_fingerprint().items():
        _raise_for_unsafe_key(fingerprint)
        if key_filename not in trusted_pub_keys:
            raise ValueError(
                "Trusted key file {} not found in fingerprint lookup".format(key_filename)
            )
        logger.info("Adding public key from file %s", key_filename)
        pubkey = _get_file_contents_from_trusted_dir_as_binary(key_filename)
        _import_public_key(gpg_home_dir, pubkey)

    # Import the trustdb
    logger.info("Importing trustdb")
    trustdb_data = _get_file_contents_from_trusted_dir_as_binary("trustdb.txt")
    _import_trust_db(gpg_home_dir, trustdb_data)


@validate(
    gpg_home_dir=NON_EMPTY_STRING,
    signing_key_fingerprint=NON_EMPTY_STRING,
    message=bytes,
    passphrase=Optional(NON_EMPTY_STRING),
)
def sign_message(gpg_home_dir, signing_key_fingerprint, message, passphrase=None):
    """Sign the given message using the key with the given fingerprint.

    ***
    N.B.: Be extra sure to avoid things that would cause a failure to sign the message, such as:
          - providing a key fingerprint that does not match any key in the GPG home directory
          - failing to provide a passphrase if the signing key requires one
          - providing an incorrect passphrase

    Doing anything that would cause GPG to be unable to sign your message will likely result
    in a SEGFAULT, abruptly crashing the Python interpreter **WITHOUT PRODUCING AN EXCEPTION**.
    ***

    Args:
        gpg_home_dir: string, the directory where GPG should look for keys and trust information
        signing_key_fingerprint: string, the hexadecimal fingerprint of the key to use for signing
        message: bytes, the message to sign
        passphrase: string, the passphrase to use to decrypt the signing key.
                    If the key is not secured with a passphrase, this argument may be omitted.
                    If the key is secured with a passphrase, this argument **MUST BE PROVIDED**.

    Returns:
        bytes, the signed cleartext message with signature applied
    """
    _raise_for_unsafe_key(signing_key_fingerprint)
    _validate_message(message)

    with gpg.Context(
        home_dir=gpg_home_dir,
        armor=True,
        offline=True,
        pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
    ) as ctx:
        warn_for_key_near_expiry(ctx)
        if passphrase is not None:

            def passphrase_cb(hint, desc, prev_bad, hook=None):
                """Callback that provides the key's passphrase when asked."""
                # If you provide a bad passphrase, GPG will just segfault.
                return passphrase

            ctx.set_passphrase_cb(passphrase_cb)

        secret_key = ctx.get_key(signing_key_fingerprint, secret=True)
        ctx.signers = [secret_key]

        signed_data, _ = ctx.sign(message, mode=gpg.constants.sig.mode.CLEAR)

        return signed_data


@validate(gpg_home_dir=NON_EMPTY_STRING, signed_data=bytes)
def verify_and_extract_message(gpg_home_dir, signed_data):
    """Verify the signature's trustworthiness, then return the binary data that was signed.

    ***
    N.B.: Be extra sure to avoid things that would cause a failure to verify the message, such as:
          - attempting to verify a corrupted message, or one with an invalid signature
          - verifying a message signed with a key that is not known or trusted by the data
            present in the GPG home directory

    Doing anything that would cause GPG to be unable to verify the message will likely result
    in a SEGFAULT, abruptly crashing the Python interpreter **WITHOUT PRODUCING AN EXCEPTION**.
    ***

    Args:
        gpg_home_dir: string, the directory where GPG should look for keys and trust information
        signed_data: bytes, the signed message to verify

    Returns:
        bytes, the signed cleartext message with signature applied
    """
    with gpg.Context(
        home_dir=gpg_home_dir,
        armor=True,
        offline=True,
        pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
    ) as ctx:
        warn_for_key_near_expiry(ctx)
        recovered_message, verification_result = ctx.verify(signed_data)

        current_time = time.time()

        # In principle, the gpg module should do all of these checks
        valid_signatures = [
            signature
            for signature in verification_result.signatures
            if all(
                (
                    # GPG has determined that the signature is valid and fully trusted.
                    signature.validity == gpg.constants.validity.FULL,
                    signature.summary == (gpg.constants.sigsum.VALID | gpg.constants.sigsum.GREEN),
                    # The signing key was not used incorrectly. An example of incorrect use would be
                    # using a key that was declared encryption-only as a signing key.
                    not signature.wrong_key_usage,
                    # The hashing algorithm used to hash the message content is sufficiently strong.
                    signature.hash_algo in TRUSTED_HASH_ALGORITHMS,
                    # The signature's timestamp isn't in the future relative to our current time.
                    signature.timestamp <= current_time,
                )
            )
        ]

        if not valid_signatures:
            raise AssertionError(
                "No valid signature found, but the gpg module did not raise "
                "an exception -- this should never happen! \n Valid signatures: {}".format(
                    verification_result.signatures
                )
            )

        return recovered_message
