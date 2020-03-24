# Copyright 2020-present Kensho Technologies, LLC.
from typing import FrozenSet, Mapping, Type

from voluptuous import Schema, validate

from .base import BaseIO
from .base_serializers import get_base_serializer_map


SERIALIZER_MAP_TYPE = Mapping[str, Type[BaseIO]]


class SerializerRegistry:
    _serializer_map = None

    def __init__(self, serializers: SERIALIZER_MAP_TYPE) -> None:
        """Make a registry"""
        self._serializer_map = serializers

    @property
    def serializer_map(self) -> SERIALIZER_MAP_TYPE:
        """Get a copy of the serializer map"""
        return dict(self._serializer_map)  # a copy

    def _assert_valid_name_and_serializer(self, name: str, serializer) -> None:
        """Check whether name and serializer are valid to be added."""
        if not isinstance(serializer(), BaseIO):
            raise TypeError(
                "Found serializer of type {}, expected `BaseIO`".format(type(serializer))
            )

        if not isinstance(name, str):
            raise TypeError("name of serialializer must be str. Found {}".format(type(name)))
        if not name:  # its empty
            raise ValueError("Name must be not empty")

        if name in self._serializer_map:
            raise KeyError("Serializer with name {} is already in the registry.".format(name))

    def register_serializer(self, name: str, serializer: Type[BaseIO]) -> None:
        """Register a new serializer"""
        self._assert_valid_name_and_serializer(name, serializer)
        self._serializer_map[name] = serializer

    @validate(mapping_of_serializers=Schema({str: type}))
    def register_multiple_serializers(self, mapping_of_serializers: SERIALIZER_MAP_TYPE) -> None:
        """Register multiple serializers."""
        # First check that all serializers in the mapping can be added
        # We check up front, because if they cannot and we repeatedly try to add them (ie if we add
        # them in an __init__ file), then after the first iteration the erroring serializer will not
        # be the actual bad serializer, but rather one of the previous ones that had already been
        # added, which leads for confusing error messages.
        for name, serializer in mapping_of_serializers.items():
            self._assert_valid_name_and_serializer(name, serializer)
        # If all serializers can be added, then add them
        for name, serializer in mapping_of_serializers.items():
            self.register_serializer(name, serializer)

    def get_serializer_by_name(self, name: str) -> Type[BaseIO]:
        """Ger a serializer by name"""
        return self._serializer_map[name]

    @property
    def available_serializers(self) -> FrozenSet[str]:
        """Get all available serializers."""
        return frozenset(self._serializer_map.keys())

    @classmethod
    def from_base(cls) -> "SerializerRegistry":
        """Make a registry from base serializers"""
        return cls(get_base_serializer_map())


REGISTRY = SerializerRegistry.from_base()
