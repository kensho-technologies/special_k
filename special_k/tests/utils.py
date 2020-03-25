# Copyright 2020-present Kensho Technologies, LLC.
import contextlib
import os
import shutil
import tempfile
import unittest

import gpg

from . import (
    _UNSAFE_KEY_PASSPHRASE,
    FAKE_KEYS_DIR,
    TESTING_ENVVAR,
    TESTING_PRIVATE_KEY_FILE,
    TRUSTED_DIR_ENVVAR,
)
from ..signing import (
    _UNSAFE_KEY_FOR_TESTING_FINGERPRINT,
    add_trusted_keys_to_gpg_home_dir,
    import_secret_key,
)
from ..utils import get_temporary_directory


class EnvvarCleanupTestCase(unittest.TestCase):
    """A helper to leave env vars untouched

    This test class sets the envvars `TESTING_ENVVAR` and `TRUSTED_DIR_ENVVAR` to their proper
    testing values for stateless tests that leave the environment unchanged. This is accomplished by
    storing the old values (should they exist), modifying the environment, and setting them back at
    when finished.

    This is done on class creation / deletion as well as surrounding every test method. While this
    is technically paranoid to do it in setUpClass/tearDownClass and in setup and teardown but it
    doesn't hurt. Additionally, doing the envvar magic in the classmethods allows children to use
    the fact that it's a testing environment.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Set up the class

        This method stores old values for `TESTING_ENVVAR` and `TRUSTED_DIR_ENVVAR` for later so
        that they can be reset to their old values on  tearDownClass. The intention is for these
        tests to have no impact on the environment
        """
        cls.cls_old_val_testing = os.environ.get(TESTING_ENVVAR)
        cls.cls_old_val_trusted_dir = os.environ.get(TRUSTED_DIR_ENVVAR)

        os.environ[TESTING_ENVVAR] = "1"
        os.environ[TRUSTED_DIR_ENVVAR] = FAKE_KEYS_DIR

    @classmethod
    def tearDownClass(cls) -> None:
        """Tear down the class

        This method reverses the setUpClass logic and resets the values for `TESTING_ENVVAR` and
        `TRUSTED_DIR_ENVVAR` back to what they used to be before the class was created
        """
        if getattr(cls, "cls_old_val_testing") is not None:
            os.environ[TESTING_ENVVAR] = getattr(cls, "cls_old_val_testing")
        else:
            os.environ.pop(TESTING_ENVVAR, None)  # it might not exist, so use pop

        if getattr(cls, "cls_old_val_trusted_dir") is not None:
            os.environ[TRUSTED_DIR_ENVVAR] = getattr(cls, "cls_old_val_trusted_dir")
        else:
            os.environ.pop(TRUSTED_DIR_ENVVAR, None)  # it might not exist, so use pop

    def setUp(self) -> None:
        """Setup before every method

        Setup before every method is called will store the old values for the env vars and reset
        them to their old values after the method runs. The reason for this is to have every test
        method run with fresh state, and not care if another test method sloppily modifies it by
        accident.
        """
        self.old_val_testing = os.environ.get(TESTING_ENVVAR)
        self.old_val_trusted_dir = os.environ.get(TRUSTED_DIR_ENVVAR)

        os.environ[TESTING_ENVVAR] = "1"
        os.environ[TRUSTED_DIR_ENVVAR] = FAKE_KEYS_DIR

    def tearDown(self) -> None:
        """Tear down after every method

        Reverse the logic in `setUp` and set envvars back to what they should be.
        """
        if getattr(self, "old_val_testing") is not None:
            os.environ[TESTING_ENVVAR] = self.old_val_testing
        else:
            os.environ.pop(TESTING_ENVVAR, None)  # it might not exist, so use pop

        if getattr(self, "old_val_trusted_dir") is not None:
            os.environ[TRUSTED_DIR_ENVVAR] = self.old_val_trusted_dir
        else:
            os.environ.pop(TRUSTED_DIR_ENVVAR, None)  # it might not exist, so use pop


class ModelBuildingTestCase(EnvvarCleanupTestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the class"""
        super(ModelBuildingTestCase, cls).setUpClass()
        cls.gpg_homedir = tempfile.mkdtemp()
        cls.key_passphrase = _UNSAFE_KEY_PASSPHRASE
        cls.gpg_context = gpg.Context(
            home_dir=cls.gpg_homedir,
            armor=True,
            offline=True,
            pinentry_mode=gpg.constants.PINENTRY_MODE_LOOPBACK,
        )
        import_secret_key(
            cls.gpg_homedir, TESTING_PRIVATE_KEY_FILE, passphrase=_UNSAFE_KEY_PASSPHRASE
        )
        signing_key = cls.gpg_context.get_key(_UNSAFE_KEY_FOR_TESTING_FINGERPRINT)
        add_trusted_keys_to_gpg_home_dir(cls.gpg_homedir)
        cls._signing_fingerprint = signing_key.fpr

    @classmethod
    def tearDownClass(cls):
        """Tear down the class"""
        shutil.rmtree(cls.gpg_homedir, ignore_errors=True)
        super(ModelBuildingTestCase, cls).tearDownClass()


@contextlib.contextmanager
def get_testing_gpg_homedir_and_context():
    """Get a temporary home directory, gpg key and fingerprint for testing signing logic

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
            import_secret_key(gpg_home_dir, TESTING_PRIVATE_KEY_FILE, _UNSAFE_KEY_PASSPHRASE)
            test_key = ctx.get_key(_UNSAFE_KEY_FOR_TESTING_FINGERPRINT)
            fingerprint = test_key.fpr
            yield gpg_home_dir, test_key, fingerprint
