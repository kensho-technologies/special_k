# Copyright 2020-present Kensho Technologies, LLC.
import os
import tarfile

from ..api import load_model_from_tarball, save_model_to_tarball
from ..exceptions import ModelValidationError
from ..serializable_model import CustomSerializedValue, SerializableModel
from ..utils import get_model_directory_name, get_temporary_directory
from .utils import ModelBuildingTestCase


TEST_KEY_ALGORITHM = "rsa1024"
TRUSTED_DIR_ENVVAR = "SERIALIZATION_TRUSTED_KEYS_DIR"


class NonPicklableObject:
    def __reduce__(self):
        raise NotImplementedError("I am not picklable, fool!")


class MockModelSkeleton(SerializableModel):
    def __init__(self):
        super(MockModelSkeleton, self).__init__()

    @property
    def _name(self):
        """das name"""
        return u"Model McModelface"

    def predict(self, X):
        """Mock predict"""
        return 42

    def validate_model(self):
        """Mock validator"""

    @property
    def custom_serialization(self):
        """Custom serializer for this simple model."""
        return {}


class MockModel(MockModelSkeleton):
    def __init__(self, a, b, metadata=None):
        """Mock model interface to test serialization and de-serialization."""
        super(MockModel, self).__init__()
        self.a = a
        self.b = b
        self.metadata = metadata

    def validate_model(self):
        """Mock validator"""
        if self.a != "good value" or self.b is not None:
            raise ModelValidationError()

    @property
    def custom_serialization(self):
        """Custom serializer for this simple model."""
        return {"a": ("json", "a.json"), "b": ("pickle", "b.pkl")}


class MockModelWithNonSerializableObject(MockModel):
    def __init__(self, a, b, metadata=None):
        super(MockModelWithNonSerializableObject, self).__init__(a, b, metadata=metadata)
        self.naughty_unpicklable_thing = NonPicklableObject()

    @property
    def custom_serialization(self):
        """Custom serializer for this simple model."""
        return {
            "a": ("json", "a.json"),
            "b": ("pickle", "b.pkl"),
            "naughty_unpicklable_thing": (None, None),
        }


class TestModelSerialization(ModelBuildingTestCase):

    def test_mock_model(self):
        mock_model = MockModel("good value", None)
        self.assertEqual(mock_model.predict("Anything"), 42)

        # Attempt to validate the model
        mock_model.validate_model()

        bad_model = MockModel("bad value", None)

        with self.assertRaises(ModelValidationError):
            bad_model.validate_model()

    def test_model_serialization(self):
        self.maxDiff = None
        metadata = {"description": "mock model"}

        mock_model = MockModel("good value", None, metadata=metadata)

        expected_files = ["b.pkl", "a.json", "meta.json.asc", "meta.version", "THEMODEL.pickle"]

        with get_temporary_directory() as temp_dir:
            tarball_path = os.path.join(temp_dir, "tarball.tar")
            save_model_to_tarball(
                mock_model,
                tarball_path,
                self.gpg_homedir,
                self._signing_fingerprint,
                self.key_passphrase,
                run_model_validation=True,
            )
            with tarfile.open(tarball_path, "r") as tar_file:
                files = tar_file.getnames()
                model_directory = get_model_directory_name(tar_file)
                self.assertSetEqual(
                    {os.path.join(model_directory, x) for x in expected_files} | {model_directory},
                    set(files),
                )

            deserialized_model = load_model_from_tarball(
                tarball_path, self.gpg_homedir, run_model_validation=True
            )
        # TODO: figure out how to test breakage in loading this model with bad pgp stuff
        self.assertIsInstance(deserialized_model, MockModel)
        self.assertEqual(mock_model.custom_serialization, deserialized_model.custom_serialization)
        self.assertEqual(mock_model.metadata, deserialized_model.metadata)
        self.assertEqual(deserialized_model.predict(u"stuff"), 42)

    def test_non_serializable_attributes(self):
        metadata = {"description": "mock model with bad attributes"}
        mock_model = MockModelWithNonSerializableObject("good value", None, metadata=metadata)

        with get_temporary_directory() as temp_dir:
            tarball_path = os.path.join(temp_dir, "tarball.tar")
            # this will fail if the naughty_unpicklable_thing is not set to CustomSerializedValue
            save_model_to_tarball(
                mock_model,
                tarball_path,
                self.gpg_homedir,
                self._signing_fingerprint,
                self.key_passphrase,
                run_model_validation=True,
            )

            deserialized_model = load_model_from_tarball(
                tarball_path, self.gpg_homedir, run_model_validation=True
            )

        self.assertIsInstance(mock_model.naughty_unpicklable_thing, CustomSerializedValue)
        self.assertIsInstance(deserialized_model, MockModelWithNonSerializableObject)
        self.assertIsNone(deserialized_model.naughty_unpicklable_thing)

    def test_invalid_model_serialization(self):
        metadata = {"description": "mock invalid model"}

        mock_invalid_model = MockModel("bad value", None, metadata=metadata)

        # this is a tricky test because we want to ensure that an invalid model cannot be saved,
        # but we also want to test that an invalid model cannot be loaded. First, assert that the
        # model fails to save when we run validation checks in `save_model_to_tarball`, then we
        # run the same code again with run_model_validation=False (don't do this in real life!)
        # so that it serializes despite its invalidity. Then we assert that the invalid model that
        # we force-saved fails to load due to validation checks in `load_model_from_tarball`
        with get_temporary_directory() as temp_dir:
            tarball_path = os.path.join(temp_dir, "tarball.tar")

            # invalid model cannot save under normal circumstances
            with self.assertRaises(ModelValidationError):
                save_model_to_tarball(
                    mock_invalid_model,
                    tarball_path,
                    self.gpg_homedir,
                    self._signing_fingerprint,
                    self.key_passphrase,
                    run_model_validation=True,
                )

            # now save invalid model to tarball and do not allow the validation checks that occur
            # by default
            save_model_to_tarball(
                mock_invalid_model,
                tarball_path,
                self.gpg_homedir,
                self._signing_fingerprint,
                self.key_passphrase,
                run_model_validation=False,
            )

            # now ensure that the invalid saved model cannot be loaded under normal circumstances
            with self.assertRaises(ModelValidationError):
                load_model_from_tarball(tarball_path, self.gpg_homedir, run_model_validation=True)

    def test_model_without_attributes(self):
        mock_model = MockModelSkeleton()
        expected_files = ["meta.json.asc", "meta.version", "THEMODEL.pickle"]

        with get_temporary_directory() as temp_dir:
            tarball_path = os.path.join(temp_dir, "tarball.tar")
            save_model_to_tarball(
                mock_model,
                tarball_path,
                self.gpg_homedir,
                self._signing_fingerprint,
                self.key_passphrase,
                run_model_validation=True,
            )
            with tarfile.open(tarball_path, "r") as tar_file:
                files = tar_file.getnames()
                model_directory = get_model_directory_name(tar_file)
                self.assertSetEqual(
                    {os.path.join(model_directory, x) for x in expected_files} | {model_directory},
                    set(files),
                )

            deserialized_model = load_model_from_tarball(
                tarball_path, self.gpg_homedir, run_model_validation=True
            )
        self.assertIsInstance(deserialized_model, MockModelSkeleton)
        self.assertEqual(mock_model.custom_serialization, deserialized_model.custom_serialization)
        self.assertEqual(deserialized_model.predict(u"stuff"), 42)
