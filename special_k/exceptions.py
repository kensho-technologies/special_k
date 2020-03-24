# Copyright 2020-present Kensho Technologies, LLC.
class ModelValidationError(Exception):
    """Raise when the model does not validate properly."""


class SerializationError(Exception):
    """Raise when a serialization related error has been encountered."""


class IntegrityError(Exception):
    """Raise when a serialized model fails integrity checks. Should never happen in practice."""


class MetadataError(Exception):
    """Raise when a model's metadata is incomplete or incorrectly formed."""
