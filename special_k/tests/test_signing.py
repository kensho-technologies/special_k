# Copyright 2020-present Kensho Technologies, LLC.
from datetime import datetime
import glob
import os
import time
from unittest.mock import Mock

import funcy
import gpg
import pytest

from . import _UNSAFE_KEY_PASSPHRASE, FAKE_KEYS_DIR, TESTING_ENVVAR, TRUSTED_DIR_ENVVAR
from ..check_gpg_keys import (
    _verify_trusted_keys_dir,
    get_keyname_to_fingerprint,
    get_trusted_pub_keys,
)
from ..signing import (
    _UNSAFE_KEY_FOR_TESTING_FINGERPRINT,
    DAYS_WARNING_FOR_KEY_EXPIRATION,
    START_OF_HISTORY,
    _is_testing,
    add_trusted_keys_to_gpg_home_dir,
    get_days_until_expiry,
    import_secret_key,
    sign_message,
    verify_and_extract_message,
    warn_for_key_near_expiry,
)
from ..utils import (
    get_gpg_homedir_and_context,
    get_key_expirations_for_gpg_context,
    get_temporary_directory,
)
from .utils import EnvvarCleanupTestCase


# WARNING: rsa1024 is NOT a secure algorithm. This is fine here because we are just testing things
# DO NOT use rsa1024 in practice. It is done here to not drain the entropy pool so the tests can
# run faster.
TEST_KEY_ALGORITHM = "rsa1024"

EXPECTED_EXTRACTED_MESSAGE = b"Test that we can sign models with gpg\n"

# Generated with the following command:
#   gpg2 --armor --clearsig --default-key 56BC24E20C87C09D3F8C76A96FD20A3075CFFAF2 my.txt
# Note that `my.txt` is the file that contains the message to be signed,
# and the hex string following `--default-key` is the signing key's fingerprint.
TESTING_KEY_SIGNED_MESSAGE = b"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Test that we can sign models with gpg
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEVrwk4gyHwJ0/jHapb9IKMHXP+vIFAlvY1+wACgkQb9IKMHXP
+vIzbwwAgUloEempNSXkeSG22zz6aCv+VCivj78WERBkCnclFPZzwFTbU0gDRnT0
NwfbUFHuTmu7d8/EDH8I4tCBfJXDg1RNuGXY/GawNqXCQ3oG1h9LP8SR1XTE8G9Y
JMqRZDIo8hBl8PCDdPy0U64h6OzM5tUrHbGMSIAr6tbP1FeqGckpeARgmGr/dwdh
nsKSGzgT9UOJGBRl+SeSgEDzxxxvHSHYGKTxy/0HChnh84+hTrbquwD9VOEPe4f3
SxNNR4LHMx9DfswBq+Jq+rzKQwogQRby/WPkSh1X8b34DeWQyzvpUOg3ubx/meZR
xxQCj7PykbEu3p77HH08w7VoAkMrHN5gr1hkkflJPIo9oJZBhndE7lhua7rrqDyW
ZFOMnTOrnkPIGFfqksv5gNs+zQr2C8g0Zk1UW6BkdABESXPKYQUoGoMdsN/0VcpT
jp3dvpx700gJkSXoWUGpSpBQuZVhT4ZqYJbDG9M51C4oDNaP3SzBzm4AQgg/ccLJ
hH928Z0H
=wYIe
-----END PGP SIGNATURE-----
"""

# Notice, all zeros in one line of the signature
MESSAGE_WITH_INVALID_SIGNATURE = b"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Test that we can sign models with gpg
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEVrwk4gyHwJ0/jHapb9IKMHXP+vIFAlvY1+wACgkQb9IKMHXP
+vIzbwwAgUloEempNSXkeSG22zz6aCv+VCivj78WERBkCnclFPZzwFTbU0gDRnT0
NwfbUFHuTmu7d8/EDH8I4tCBfJXDg1RNuGXY/GawNqXCQ3oG1h9LP8SR1XTE8G9Y
JMqRZDIo8hBl8PCDdPy0U64h6OzM5tUrHbGMSIAr6tbP1FeqGckpeARgmGr/dwdh
0000000000000000000000000000000000000000000000000000000000000000
SxNNR4LHMx9DfswBq+Jq+rzKQwogQRby/WPkSh1X8b34DeWQyzvpUOg3ubx/meZR
xxQCj7PykbEu3p77HH08w7VoAkMrHN5gr1hkkflJPIo9oJZBhndE7lhua7rrqDyW
ZFOMnTOrnkPIGFfqksv5gNs+zQr2C8g0Zk1UW6BkdABESXPKYQUoGoMdsN/0VcpT
jp3dvpx700gJkSXoWUGpSpBQuZVhT4ZqYJbDG9M51C4oDNaP3SzBzm4AQgg/ccLJ
hH928Z0H
=wYIe
-----END PGP SIGNATURE-----
"""

MUTATED_MESSAGE_WITH_MISMATCHED_SIGNATURE = b"""-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Not what the original message contained
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEVrwk4gyHwJ0/jHapb9IKMHXP+vIFAlvY1+wACgkQb9IKMHXP
+vIzbwwAgUloEempNSXkeSG22zz6aCv+VCivj78WERBkCnclFPZzwFTbU0gDRnT0
NwfbUFHuTmu7d8/EDH8I4tCBfJXDg1RNuGXY/GawNqXCQ3oG1h9LP8SR1XTE8G9Y
JMqRZDIo8hBl8PCDdPy0U64h6OzM5tUrHbGMSIAr6tbP1FeqGckpeARgmGr/dwdh
nsKSGzgT9UOJGBRl+SeSgEDzxxxvHSHYGKTxy/0HChnh84+hTrbquwD9VOEPe4f3
SxNNR4LHMx9DfswBq+Jq+rzKQwogQRby/WPkSh1X8b34DeWQyzvpUOg3ubx/meZR
xxQCj7PykbEu3p77HH08w7VoAkMrHN5gr1hkkflJPIo9oJZBhndE7lhua7rrqDyW
ZFOMnTOrnkPIGFfqksv5gNs+zQr2C8g0Zk1UW6BkdABESXPKYQUoGoMdsN/0VcpT
jp3dvpx700gJkSXoWUGpSpBQuZVhT4ZqYJbDG9M51C4oDNaP3SzBzm4AQgg/ccLJ
hH928Z0H
=wYIe
-----END PGP SIGNATURE-----
"""


def _get_fingerprints_in_trust_db(trustdb_path):
    """Get fingerprints (and associated trust levels) in a trustdb file"""
    with open(trustdb_path, "r") as fi:
        trustdb = fi.readlines()
    fingerprints_in_db = [
        entry.strip()  # remove comments, whitespace, and newlines from trustdb
        for entry in trustdb
        if not entry.startswith("#")
    ]
    return fingerprints_in_db


def _write_contents_to_file(filepath, contents):
    """Write contents to a file."""
    with open(filepath, "w") as fi:
        fi.write(contents)


class TestFakeKeySafety(EnvvarCleanupTestCase):
    def test_testing_usage(self):
        # test that we can properly verify a message signed by the test directory if we set the
        # trusted keys directory to the unsafe one and enable the testing flag
        os.environ[TESTING_ENVVAR] = "1"
        os.environ[TRUSTED_DIR_ENVVAR] = FAKE_KEYS_DIR
        with get_temporary_directory() as gpg_home_dir:
            add_trusted_keys_to_gpg_home_dir(gpg_home_dir)

            # Sanity-check: ensure that the valid signed message is still accepted and trusted.
            self.assertEqual(
                EXPECTED_EXTRACTED_MESSAGE,
                verify_and_extract_message(gpg_home_dir, TESTING_KEY_SIGNED_MESSAGE),
            )

        # unset the testing flag, it should now raise RuntimeError
        del os.environ[TESTING_ENVVAR]
        with get_temporary_directory() as gpg_home_dir:
            with self.assertRaises(RuntimeError):
                add_trusted_keys_to_gpg_home_dir(gpg_home_dir)

        # Now delete the trusted keys dir. We should get a value error when trying to find it
        del os.environ[TRUSTED_DIR_ENVVAR]
        with get_temporary_directory() as gpg_home_dir:
            with self.assertRaises(ValueError):
                add_trusted_keys_to_gpg_home_dir(gpg_home_dir)

    def test__is_testing(self):
        if TESTING_ENVVAR in os.environ:
            del os.environ[TESTING_ENVVAR]
        self.assertFalse(_is_testing())

        os.environ[TESTING_ENVVAR] = "1"
        self.assertTrue(_is_testing())

        os.environ[TESTING_ENVVAR] = "0"
        self.assertFalse(_is_testing())

        for bad_val in ("2", "-1", "a string", "1.0", "False", "True"):
            os.environ[TESTING_ENVVAR] = bad_val
            with self.assertRaises(ValueError):
                _is_testing()


class SigningTests(EnvvarCleanupTestCase):
    def test_reinitialization_is_safe(self):
        with get_temporary_directory() as gpg_home_dir:
            # this is now fsync'ed for safety

            # Add ultimately trusted key to the home dir twice.
            # The second time should have no effect.
            add_trusted_keys_to_gpg_home_dir(gpg_home_dir)
            add_trusted_keys_to_gpg_home_dir(gpg_home_dir)

            # Sanity-check: ensure that the valid signed message is still accepted and trusted.
            self.assertEqual(
                EXPECTED_EXTRACTED_MESSAGE,
                verify_and_extract_message(gpg_home_dir, TESTING_KEY_SIGNED_MESSAGE),
            )

    def test_sign_and_verify_with_new_key(self):
        passphrase = None
        with get_gpg_homedir_and_context(passphrase, algorithm=TEST_KEY_ALGORITHM) as (
            gpg_home_dir,
            new_key,
            key_fingerprint,
        ):
            test_message = b"Hello world! This is a test!\n"
            signed_data = sign_message(gpg_home_dir, key_fingerprint, test_message)

            recovered_message = verify_and_extract_message(gpg_home_dir, signed_data)
            self.assertEqual(test_message, recovered_message)

            with self.assertRaises(ValueError):
                # GPG seems to like adding a newline to the end of the extracted message,
                # regardless of whether or not the original message contained a newline.
                # For safety, we don't allow messages that do not end in a newline to be signed.
                sign_message(
                    gpg_home_dir, key_fingerprint, b"message that does not end in a newline"
                )

            # The new GPG home dir does not trust the ultimately trusted key.
            # We can use this fact to test that invalid signatures are not respected.
            # TODO: Since the signature is from an unknown pubkey, that causes a SEGFAULT
            #                that crashes the python interpreter, stopping the tests.
            #                See if anything can be done in this case.
            # with self.assertRaises(gpg.errors.VerificationError):
            #     verify_and_extract_message(gpg_home_dir, MASTER_KEY_SIGNED_MESSAGE)

    def test_sign_and_verify_with_key_and_passphrase(self):
        passphrase = "test_sign_and_verify_with_key_and_passphrase"

        with get_gpg_homedir_and_context(passphrase, algorithm=TEST_KEY_ALGORITHM) as (
            gpg_home_dir,
            new_key,
            key_fingerprint,
        ):
            test_message = b"Hello world! This is a test!\n"
            signed_data = sign_message(
                gpg_home_dir, key_fingerprint, test_message, passphrase=passphrase
            )

            recovered_message = verify_and_extract_message(gpg_home_dir, signed_data)
            self.assertEqual(test_message, recovered_message)

    def test_import_private_key(self):
        private_key_path = os.path.join(FAKE_KEYS_DIR, "testing.secret.asc")
        with get_temporary_directory() as gpg_home_dir:
            import_secret_key(gpg_home_dir, private_key_path, passphrase=_UNSAFE_KEY_PASSPHRASE)
            with gpg.Context(home_dir=gpg_home_dir) as ctx:
                keys = list(ctx.keylist())
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0].fpr, _UNSAFE_KEY_FOR_TESTING_FINGERPRINT)

    @pytest.mark.skip("GPG will segfault if we provide a bad passphrase, and we cannot test that")
    def test_attempt_signing_with_bad_passphrase(self):
        passphrase = "test_attempt_signing_with_bad_passphrase"
        with get_gpg_homedir_and_context(passphrase, algorithm=TEST_KEY_ALGORITHM) as (
            gpg_home_dir,
            new_key,
            key_fingerprint,
        ):

            test_message = b"Hello world! This is a test!\n"

            # Using an incorrect passphrase for the key will result in an error.
            with self.assertRaises(AssertionError):
                sign_message(
                    gpg_home_dir, key_fingerprint, test_message, passphrase="incorrect passphrase"
                )


class ExpiryTests(EnvvarCleanupTestCase):
    def test_key_expiry_utils(self):
        seconds_in_a_day = 86400
        with get_temporary_directory() as gpg_home_dir:
            # gpg_home_dir is now fsync'ed
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                new_key_long_expiry = ctx.create_key(
                    "test@example.com",
                    # make the key expire in much more than the expiration
                    # give an extra 60s because key creation can take more than a second
                    expires_in=DAYS_WARNING_FOR_KEY_EXPIRATION * seconds_in_a_day * 2 + 60,
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                key_expirations = list(get_key_expirations_for_gpg_context(ctx).items())
                self.assertEqual(len(key_expirations), 1)  # there should only be one key
                fpr, expiry = key_expirations[0]
                self.assertEqual(fpr, new_key_long_expiry.fpr)
                day_to_expiry = (expiry - datetime.now()).days
                # TODO: Determine why this test fails occasionally with day_to_expiry off by one
                self.assertAlmostEqual(day_to_expiry, 2 * DAYS_WARNING_FOR_KEY_EXPIRATION, delta=1)

        # now test keys with no expiration
        with get_temporary_directory() as gpg_home_dir:
            # gpg_home_dir is now fsync'ed
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                new_key_no_expiry = ctx.create_key(
                    "test@example.com",
                    # make the key that never expires
                    expires=False,
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                key_expirations = list(get_key_expirations_for_gpg_context(ctx).items())
                self.assertEqual(len(key_expirations), 1)  # there should only be one key
                fpr, expiry = key_expirations[0]
                self.assertEqual(fpr, new_key_no_expiry.fpr)
                self.assertEqual(expiry, START_OF_HISTORY)
                days_until_expiry = get_days_until_expiry(ctx)[fpr]
                self.assertEqual(days_until_expiry, float("inf"))

    def test_expiry_warning(self):
        with get_temporary_directory() as gpg_home_dir:
            # gpg_home_dir is now fsync'ed
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                new_key_short_expiry = ctx.create_key(
                    "test@example.com",
                    # make the key expire in much more than the expiration
                    expires_in=60 * 60,  # expires in an hour
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                key_expirations = list(get_key_expirations_for_gpg_context(ctx).items())
                self.assertEqual(len(key_expirations), 1)  # there should only be one key
                fpr, expiry = key_expirations[0]
                self.assertEqual(fpr, new_key_short_expiry.fpr)
                day_to_expiry = (expiry - datetime.now()).days
                self.assertEqual(day_to_expiry, 0)
                with self.assertLogs("special_k.signing", level="WARNING"):
                    warn_for_key_near_expiry(ctx)

    def test_contradictory_expiry_info(self):
        # Test a key that is marked as expired, despite having an expiration date in the future
        with get_temporary_directory() as gpg_home_dir:
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                ctx.create_key(
                    "test@example.com",
                    expires_in=24 * 60 * 60,
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                keylist = list(ctx.keylist())
                new_key = keylist[0]
                new_key.expired = 1
                ctx.get_key = Mock(return_value=new_key)

                with self.assertRaisesRegex(
                    AssertionError, "Key with fingerprint .* is marked as expired"
                ):
                    get_key_expirations_for_gpg_context(ctx)

        # Test a key that is marked as unexpired, despite having an expiration date in the past
        with get_temporary_directory() as gpg_home_dir:
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                ctx.create_key(
                    "test@example.com",
                    expires_in=1,
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                time.sleep(1)  # Wait until the key expires
                keylist = list(ctx.keylist())
                new_key = keylist[0]
                new_key.expired = 0
                ctx.get_key = Mock(return_value=new_key)

                with self.assertRaisesRegex(
                    AssertionError, "Key with fingerprint .* is marked as not expired"
                ):
                    get_key_expirations_for_gpg_context(ctx)

        # Test a key that is marked as expired, but never expires
        with get_temporary_directory() as gpg_home_dir:
            with gpg.Context(
                home_dir=gpg_home_dir,
                armor=True,
                offline=True,
                pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
            ) as ctx:
                ctx.create_key(
                    "test@example.com",
                    expires=False,
                    algorithm=TEST_KEY_ALGORITHM,
                    sign=True,
                    passphrase=None,
                )
                keylist = list(ctx.keylist())
                new_key = keylist[0]
                new_key.expired = 1
                ctx.get_key = Mock(return_value=new_key)

                with self.assertRaisesRegex(
                    AssertionError, "Key with fingerprint .* has no expiration date"
                ):
                    get_key_expirations_for_gpg_context(ctx)


class TestTrustedKeys(EnvvarCleanupTestCase):
    def test_checked_in_keys(self):
        # test that there is a one to one map between checked in keys and fingerprints
        keyname_to_fingerprint = get_keyname_to_fingerprint()
        self.assertEqual(set(get_trusted_pub_keys()), set(keyname_to_fingerprint.keys()))
        self.assertIn(_UNSAFE_KEY_FOR_TESTING_FINGERPRINT, keyname_to_fingerprint.values())

        # Make sure people don't mess with the trusted_keys directory
        cur_path = os.path.dirname(os.path.abspath(__file__))
        trusted_keys_dir = os.path.join(cur_path, "./fake_keys")
        trustdb_path = os.path.join(trusted_keys_dir, "trustdb.txt")

        # enumerate all the possible files that might have accidentally ended up in trusted_keys
        # If someone has good reason to add a .py file (other than __init__), then can delete
        # that extension from here
        file_patterns_to_check = ("*.py", "*.txt", "*.key", "*.pem", "*.pub*", "*.asc")
        all_files_in_trusted_keys_dir = funcy.flatten(
            glob.glob(os.path.join(trusted_keys_dir, pattern)) for pattern in file_patterns_to_check
        )

        all_file_names = {  # take basename and fine uniques
            os.path.basename(filepath) for filepath in all_files_in_trusted_keys_dir
        }

        expected_filenames = get_trusted_pub_keys().union(
            {"trustdb.txt", "__init__.py", "my.txt.asc", "testing.secret.asc"}
        )
        # expected_filenames is a frozenset, need to cast to set for nice debugging
        self.assertEqual(all_file_names, set(expected_filenames))

        # test that only the ultimately trusted key is in the trustdb
        fingerprints_in_trust_db = _get_fingerprints_in_trust_db(trustdb_path)
        self.assertEqual(
            len(fingerprints_in_trust_db),
            1,
            "Found {} items in trustdb. Expected 1. Someone has added keys to the "
            "trustdb but only the ultimately trusted key should be "
            "there".format(len(fingerprints_in_trust_db)),
        )
        expected_entry = "{}:6:".format(_UNSAFE_KEY_FOR_TESTING_FINGERPRINT)
        self.assertEqual(
            fingerprints_in_trust_db[0],
            expected_entry,
            "Found a single entry, `{}` in the trustdb but it does not match the "
            "ultimately trusted key. Only the ultimately trusted key should live inside the "
            "trust db.".format(fingerprints_in_trust_db[0]),
        )

    def test__verify_trusted_keys_dir(self):
        # get everything right
        with get_temporary_directory() as trusted_keys_dir:
            filepath = os.path.join(trusted_keys_dir, "key1.pub.asc")
            _write_contents_to_file(filepath, "this is a key")

            filepath = os.path.join(trusted_keys_dir, "trustdb.txt")
            _write_contents_to_file(filepath, "this is a trustdb")

            filepath = os.path.join(trusted_keys_dir, "keyname-to-fingerprint.json")
            _write_contents_to_file(filepath, "this is a json map")

            _verify_trusted_keys_dir(trusted_keys_dir)

        # no public key
        with get_temporary_directory() as trusted_keys_dir:

            filepath = os.path.join(trusted_keys_dir, "trustdb.txt")
            _write_contents_to_file(filepath, "this is a trustdb")

            filepath = os.path.join(trusted_keys_dir, "keyname-to-fingerprint.json")
            _write_contents_to_file(filepath, "this is a json map")

            with self.assertRaisesRegex(ValueError, "No public keys.*"):
                _verify_trusted_keys_dir(trusted_keys_dir)

        # no trustdb
        with get_temporary_directory() as trusted_keys_dir:
            filepath = os.path.join(trusted_keys_dir, "key1.pub.asc")
            _write_contents_to_file(filepath, "this is a key")

            filepath = os.path.join(trusted_keys_dir, "keyname-to-fingerprint.json")
            _write_contents_to_file(filepath, "this is a json map")

            with self.assertRaisesRegex(ValueError, "No `trustdb.txt`.*"):
                _verify_trusted_keys_dir(trusted_keys_dir)

        # keyname to fingerprint
        with get_temporary_directory() as trusted_keys_dir:
            filepath = os.path.join(trusted_keys_dir, "key1.pub.asc")
            _write_contents_to_file(filepath, "this is a key")

            filepath = os.path.join(trusted_keys_dir, "trustdb.txt")
            _write_contents_to_file(filepath, "this is a trustdb")

            with self.assertRaisesRegex(ValueError, "No file `keyname-to-fingerprint.*"):
                _verify_trusted_keys_dir(trusted_keys_dir)
