# Copyright 2020-present Kensho Technologies, LLC.
from unittest import TestCase
from unittest.mock import patch

import setuptools


class TestExtrasRequire(TestCase):
    def test_extras_require(self):
        # Test that we don't inadvertently delete an expected dependency from
        # setup.py extras_require by asserting it exists where it should.
        # If a feature becomes obsolete, set its value to None rather than
        # deleting the entry. For instance, {"PDF": None}

        with patch.object(setuptools, "setup") as mock_setup:
            import setup  # noqa: F401

            _, kwargs = mock_setup.call_args
            extras_require = kwargs.get("extras_require")
            self.assertIsNotNone(extras_require)
            self.assertIn("Keras", extras_require)
