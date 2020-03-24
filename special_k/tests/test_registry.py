# Copyright 2020-present Kensho Technologies, LLC.
import unittest

from ..serializers.base import BaseIO
from ..serializers.base_serializers import PickleIO, get_base_serializer_map
from ..serializers.registry import SerializerRegistry


class MockSerializer(BaseIO):
    @staticmethod
    def _deserialize_from_stream(stream):
        """Deserialize from a stream"""

    @staticmethod
    def _serialize_to_stream(item, stream):
        """Serialize to a stream"""


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.REGISTRY = SerializerRegistry.from_base()

    def test_registry(self):
        expected_serializers = frozenset(get_base_serializer_map().keys())
        self.assertEqual(self.REGISTRY.available_serializers, expected_serializers)

    def test_registering_serializers(self):
        new_name = "cool-new-thing"
        self.REGISTRY.register_serializer(new_name, MockSerializer)
        self.assertEqual(self.REGISTRY.get_serializer_by_name(new_name), MockSerializer)
        self.assertIn(new_name, self.REGISTRY.available_serializers)

        # make sure we cannot register the same thing twice
        with self.assertRaises(KeyError):
            self.REGISTRY.register_serializer(new_name, MockSerializer)

        # make sure we can't have empty strings
        with self.assertRaises(ValueError):
            self.REGISTRY.register_serializer("", PickleIO)

        class NotABaseIO:
            """This class looks like a BaseIO but does not inherit from it."""

            @staticmethod
            def _deserialize_from_stream(stream):
                """Deserialize from a stream"""

            @staticmethod
            def _serialize_to_stream(item, stream):
                """Serialize to a stream"""

        with self.assertRaises(TypeError):
            self.REGISTRY.register_serializer("name-should-not-matter", NotABaseIO)

    def test_registering_multiple_serializer(self):
        mock_name_1 = "mock_serializer_1"
        mock_name_2 = "mock_serializer_2"
        new_serializers = {mock_name_1: MockSerializer, mock_name_2: MockSerializer}
        self.REGISTRY.register_multiple_serializers(new_serializers)
        self.assertIn(mock_name_1, self.REGISTRY.available_serializers)
        self.assertIn(mock_name_2, self.REGISTRY.available_serializers)

        # Test that if all serializers cannot be added, then none are
        mock_name_a = "mock_serializer_a"
        mock_name_2 = "mock_serializer_2"
        new_serializers = {
            mock_name_a: MockSerializer,
            mock_name_2: MockSerializer,  # Already in mapping (from above)
        }
        with self.assertRaises(KeyError):
            self.REGISTRY.register_multiple_serializers(new_serializers)
        self.assertNotIn(mock_name_a, self.REGISTRY.available_serializers)
