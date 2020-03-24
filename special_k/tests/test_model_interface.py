# Copyright 2020-present Kensho Technologies, LLC.
import unittest

from ..serializable_model import SerializableModel


class MockModel(SerializableModel):
    """The methods below are there to implement the abstract interface."""

    def __init__(self, a, b, metadata=None):
        """Mock model interface to test serialization and de-serialization."""
        super(MockModel, self).__init__()
        self.metadata = metadata
        self.a = a
        self.b = b

    @property
    def custom_serialization(self):
        """Custom Serialization"""
        return {}

    def validate_model(self):
        """Validate model"""

    def predict(self, X):
        """Predict stuff."""


class TestModelInterface(unittest.TestCase):
    """Test model interface."""

    def test_metadata_setter(self):
        """Test that metadata is set with metadata setter."""
        my_model = MockModel("a", "b")  # no metadata
        self.assertIsNone(my_model.metadata, None)

        # check that we can overwrite None to None
        my_model.metadata = None
        self.assertEqual(my_model.metadata, None)
        self.assertEqual(my_model._metadata, None)

        # check that we can set it to a dict
        kosher_metadata = {"a": 1}
        my_model.metadata = {k: v for k, v in kosher_metadata.items()}  # want a copy of it
        self.assertEqual(my_model.metadata, kosher_metadata)
        self.assertEqual(my_model._metadata, kosher_metadata)

        # check that we can't set it to a bad type
        my_model = MockModel("a", "b")
        naughty_metadata = "this is a list".split()
        with self.assertRaises(TypeError):
            my_model.metadata = naughty_metadata

        # check that we can't overwrite metadata if it's already written
        new_model = MockModel("a", "b", metadata={"b": 1})
        with self.assertRaises(AssertionError):
            new_model.metadata = kosher_metadata

        with self.assertRaises(AssertionError):
            new_model.metadata = None

    def test_abstract_methods(self):
        class GoodModel(SerializableModel):
            @property
            def _name(self):
                """This is the name"""
                return "a model"

            @property
            def custom_serialization(self):
                """Custom Serialization"""
                return {}

            def validate_model(self):
                """Validate model"""

            def predict(self, X):
                """Predict stuff."""

        class IncompleteModel(SerializableModel):
            """This class does not implement `validate_model`"""

            @property
            def _name(self):
                """This is the name"""
                return "a model"

            @property
            def custom_serialization(self):
                """Custom Serialization"""
                return {}

            def predict(self, X):
                """Predict stuff."""

        good_model = GoodModel()
        self.assertIsInstance(good_model, GoodModel)

        with self.assertRaisesRegex(TypeError, "Can't instantiate abstract class*"):
            IncompleteModel()
