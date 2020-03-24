# Copyright 2020-present Kensho Technologies, LLC.
"""All of the ways we know how to write and read things"""
import codecs
from collections import OrderedDict
from io import BytesIO
import json
import logging
import pickle
from typing import Any, Dict, NamedTuple

import dill
import joblib
import msgpack
from voluptuous import Optional, Schema, validate

from .base import PATH_TYPE, BaseIO
from .utils import (
    STREAM_TYPE,
    deserialize_from_temp_h5py,
    read_json_from_stream,
    serialize_to_temp_h5py,
    write_json_to_stream,
)


logger = logging.getLogger(__name__)


class JsonIO(BaseIO):
    @staticmethod
    def _serialize_to_stream(item: Any, stream: STREAM_TYPE) -> int:
        """Serialize to a stream: this is a hack to make sure we write bytes in py3"""
        return write_json_to_stream(item, stream)

    @staticmethod
    def _deserialize_from_stream(stream: STREAM_TYPE) -> Any:
        """De-serialize from a stream: this is a hack to make sure we read bytes in py3"""
        return read_json_from_stream(stream)

    @staticmethod
    def dump(item: Any, filepath: PATH_TYPE) -> None:
        """Serialize to disk"""
        with codecs.open(filepath, "w", encoding="utf-8") as fi:
            json.dump(item, fi)

    @staticmethod
    def load(filepath: PATH_TYPE) -> Any:
        """Deserialize from disk"""
        with codecs.open(filepath, "r", encoding="utf-8") as fi:
            item = json.load(fi)
        return item


class PickleIO(BaseIO):
    _serialize_to_stream = staticmethod(pickle.dump)
    _deserialize_from_stream = staticmethod(pickle.load)

    @staticmethod
    def dump(item: Any, filepath: PATH_TYPE) -> None:
        """Serialize to disk"""
        with codecs.open(filepath, "wb") as fi:
            pickle.dump(item, fi)

    @staticmethod
    def load(filepath: PATH_TYPE) -> Any:
        """Deserialize from disk"""
        with codecs.open(filepath, "rb") as fi:
            item = pickle.load(fi)
        return item


class MsgPackIO(BaseIO):
    @staticmethod
    def _serialize_to_stream(item: Any, stream: STREAM_TYPE) -> None:
        """Serialize to stream"""
        # can't define staticmethods as above because kwargs are necessary to preserve binary/string
        # types in python3
        return msgpack.dump(item, stream, use_bin_type=True)

    @staticmethod
    def _deserialize_from_stream(stream: STREAM_TYPE) -> Any:
        """Deserialize from stream"""
        # can't define staticmethods as above because kwargs are necessary to preserve binary/string
        # types in python3
        return msgpack.load(stream, raw=False)

    @staticmethod
    def dump(item: Any, filepath: PATH_TYPE) -> None:
        """Serialize to disk"""
        with codecs.open(filepath, "wb") as fi:
            msgpack.dump(item, fi, use_bin_type=True)

    @staticmethod
    def load(filepath: PATH_TYPE) -> Any:
        """Deserialize from disk"""
        with codecs.open(filepath, "rb") as fi:
            item = msgpack.load(fi, raw=False)
        return item


class DillIO(BaseIO):
    _serialize_to_stream = staticmethod(dill.dump)
    _deserialize_from_stream = staticmethod(dill.load)

    @staticmethod
    def dump(item: Any, filepath: PATH_TYPE) -> None:
        """Serialize to disk"""
        with codecs.open(filepath, "wb") as fi:
            dill.dump(item, fi)

    @staticmethod
    def load(filepath: PATH_TYPE) -> Any:
        """Deserialize from disk"""
        with codecs.open(filepath, "rb") as fi:
            item = dill.load(fi)
        return item


class JoblibIO(BaseIO):
    _serialize_to_stream = staticmethod(joblib.dump)
    _deserialize_from_stream = staticmethod(joblib.load)

    @staticmethod
    def dump(item: Any, filepath: PATH_TYPE) -> None:
        """Serialize to disk"""
        with codecs.open(filepath, "wb") as fi:
            joblib.dump(item, fi)

    @staticmethod
    def load(filepath: PATH_TYPE) -> Any:
        """Deserialize from disk"""
        with codecs.open(filepath, "rb") as fi:
            item = joblib.load(fi)
        return item


try:
    from tensorflow import keras

    include_keras = True

    class KerasCustomComponent(NamedTuple):
        keras_model: keras.models.Model
        custom_objects: dict

    KERAS_CUSTOM_SERIALIZED_FORMAT = Schema(
        {"keras_model": bytes, "custom_objects": Optional(dict)}, required=True
    )

    class KerasIO(BaseIO):
        @staticmethod
        def _serialize_to_stream(item: Any, stream: STREAM_TYPE) -> None:
            """Serialize `item` to a stream"""
            serialize_to_temp_h5py(item, stream, KerasIO.dump)

        @staticmethod
        def _deserialize_from_stream(stream: STREAM_TYPE) -> keras.models.Model:
            """Deserialize the object in the given stream."""
            model = deserialize_from_temp_h5py(stream, KerasIO.load)
            return model

        @staticmethod
        def dump(item: Any, filepath: PATH_TYPE) -> None:
            """Serialize to disk"""
            keras.models.save_model(item, filepath)

        @staticmethod
        def load(filepath: PATH_TYPE) -> keras.models.Model:
            """Deserialize from disk"""
            return keras.models.load_model(filepath)

    class KerasCustomObjectsIO(BaseIO):
        CUSTOM_OBJECT_ATTR_NAME = "custom_objects_for_serialization"

        @staticmethod
        def _check_custom_objects(model: KerasCustomComponent) -> None:
            """Check that a keras model is well-formed for serialization"""
            custom_objects = model.custom_objects
            if not isinstance(custom_objects, dict):
                raise TypeError(
                    "Found model with attribute {} of type {}. Expected dict with keys of type str."
                    "".format(KerasCustomObjectsIO.CUSTOM_OBJECT_ATTR_NAME, type(custom_objects))
                )
            if not all(
                isinstance(k, str) for k in custom_objects
            ):  # make sure all the keys are str
                key_and_types = {k: type(k) for k in custom_objects}
                raise ValueError(
                    "Expected attribute {} for be dict with keys of type str. "
                    "Found keys and types: {}"
                    "".format(KerasCustomObjectsIO.CUSTOM_OBJECT_ATTR_NAME, key_and_types)
                )

        @staticmethod
        def _partially_serialize(item: KerasCustomComponent) -> Dict[str, Any]:
            """Partially serialize a model (write the keras model to a string)"""
            KerasCustomObjectsIO._check_custom_objects(item)
            bio = BytesIO()
            serialize_to_temp_h5py(item.keras_model, bio, KerasIO.dump)
            bio.seek(0)
            partially_serialized = {
                "keras_model": bio.read(),
                "custom_objects": item.custom_objects,
            }
            return partially_serialized

        @staticmethod
        @validate(item=KERAS_CUSTOM_SERIALIZED_FORMAT)
        def _complete_deserialization(item: Any) -> KerasCustomComponent:
            """Complete deserialization: load the keras model from a string with custom objects"""
            stream_with_model_only = BytesIO(item["keras_model"])
            custom_objects = item["custom_objects"]
            model = deserialize_from_temp_h5py(
                stream_with_model_only,
                lambda x: keras.models.load_model(x, custom_objects=custom_objects),
            )
            return KerasCustomComponent(model, custom_objects)

        @staticmethod
        def _serialize_to_stream(item: Any, stream: STREAM_TYPE) -> None:
            """Serialize `item` to a stream

            This code requires keras version 2.1.6 or later!
            """
            partially_serialized = KerasCustomObjectsIO._partially_serialize(item)
            PickleIO._serialize_to_stream(partially_serialized, stream)

        @staticmethod
        def _deserialize_from_stream(stream: STREAM_TYPE) -> KerasCustomComponent:
            """Deserialize the object in the given stream."""
            partially_deserialized = PickleIO._deserialize_from_stream(stream)
            return KerasCustomObjectsIO._complete_deserialization(partially_deserialized)

        @staticmethod
        def dump(item: Any, filepath: PATH_TYPE) -> None:
            """Serialize to disk"""
            partially_serialized = KerasCustomObjectsIO._partially_serialize(item)
            PickleIO.dump(partially_serialized, filepath)

        @staticmethod
        def load(filepath: PATH_TYPE) -> KerasCustomComponent:
            """Deserialize from disk"""
            partially_deserialized = PickleIO.load(filepath)
            return KerasCustomObjectsIO._complete_deserialization(partially_deserialized)


except ImportError:
    include_keras = False


try:
    import torch

    include_torch = True
    # We are only allowing new torch zipfile serialization (starts in v1.4) because it is less
    # error prone (fewer files lying around) and we don't want to deal with migrating the old-style
    # models (multiple files) to work with newer versions
    # TODO(team): when an official release is cut that removes this kwarg, remove it from here
    save_kwargs = {"_use_new_zipfile_serialization": True}

    class TorchModelIO(BaseIO):
        @staticmethod
        def _serialize_to_stream(item: torch.nn.Module, stream: STREAM_TYPE) -> None:
            """Serialize `item` to a stream"""
            torch.save(item, stream, **save_kwargs)

        @staticmethod
        def _deserialize_from_stream(stream: STREAM_TYPE) -> torch.nn.Module:
            """Deserialize the object in the given stream."""
            model = torch.load(stream)
            model.eval()
            return model

        @staticmethod
        def dump(item: torch.nn.Module, filepath: PATH_TYPE) -> None:
            """Serialize to disk"""
            torch.save(item, filepath, **save_kwargs)

        @staticmethod
        def load(filepath: PATH_TYPE) -> torch.nn.Module:
            """Deserialize from disk"""
            model = torch.load(filepath)
            return model

    class TorchStateDictIO(BaseIO):
        @staticmethod
        def _serialize_to_stream(item: torch.nn.Module, stream: STREAM_TYPE) -> None:
            """Serialize `item` to a stream"""
            torch.save(item, stream, **save_kwargs)

        @staticmethod
        def _deserialize_from_stream(stream: STREAM_TYPE) -> OrderedDict:
            """Deserialize the object in the given stream."""
            state_dict = torch.load(stream)
            return state_dict

        @staticmethod
        def dump(item: torch.nn.Module, filepath: PATH_TYPE) -> None:
            """Serialize to disk"""
            torch.save(item, filepath, **save_kwargs)

        @staticmethod
        def load(filepath: PATH_TYPE) -> OrderedDict:
            """Deserialize from disk"""
            state_dict = torch.load(filepath)
            return state_dict


except ImportError:
    include_torch = False


SERIALIZER_PICKLE = "pickle"
SERIALIZER_MSGPACK = "msgpack"
SERIALIZER_JSON = "json"
SERIALIZER_JOBLIB = "jlib"
SERIALIZER_KERAS = "keras"
SERIALIZER_KERAS_WITH_CUSTOM_OBJECTS = "keras_with_custom_objects"
SERIALIZER_TORCH_MODEL = "torch"
SERIALIZER_TORCH_STATE_DICT = "torch_state_dict"
SERIALIZER_DILL = "dill"


def get_base_serializer_map():
    """Get the base serializer map."""
    base_serializer_map = {
        SERIALIZER_PICKLE: PickleIO,
        SERIALIZER_MSGPACK: MsgPackIO,
        SERIALIZER_JSON: JsonIO,
        SERIALIZER_JOBLIB: JoblibIO,
        SERIALIZER_DILL: DillIO,
    }
    if include_keras:
        base_serializer_map.update(
            {SERIALIZER_KERAS: KerasIO, SERIALIZER_KERAS_WITH_CUSTOM_OBJECTS: KerasCustomObjectsIO}
        )
    if include_torch:
        base_serializer_map.update(
            {SERIALIZER_TORCH_MODEL: TorchModelIO, SERIALIZER_TORCH_STATE_DICT: TorchStateDictIO}
        )
    return base_serializer_map
