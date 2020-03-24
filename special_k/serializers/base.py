# Copyright 2020-present Kensho Technologies, LLC.
import os
from typing import IO, Any, Tuple, Union

from ..verifiable_stream import VerifiableStream, verify_stream


STREAM_TYPE = IO
PATH_TYPE = Union[str, os.PathLike]


class BaseIO:
    @classmethod
    def to_verifiable_stream(cls, item: Any) -> Tuple[VerifiableStream, str, str]:
        """Serialize the object to a stream, returning it together with a nonce and HMAC code."""
        stream = VerifiableStream()

        cls._serialize_to_stream(item, stream)
        nonce, hmac_code = stream.finalize()

        return stream, nonce, hmac_code

    @classmethod
    def from_verifiable_stream(cls, stream: STREAM_TYPE, nonce: str, hmac_code: str) -> Any:
        """Deserialize the object from a stream, verifying its integrity in the process."""
        # Ensure the stream's integrity before doing any operations on it.
        # If verification fails, the below function will raise an exception.
        verify_stream(nonce, hmac_code, stream)

        return cls._deserialize_from_stream(stream)

    @staticmethod
    def _serialize_to_stream(item: Any, stream: STREAM_TYPE) -> None:
        """Serialize the object to the given stream, without closing the stream."""
        raise NotImplementedError("you must override me")

    @staticmethod
    def _deserialize_from_stream(stream: STREAM_TYPE) -> Any:
        """Return the deserialized object present in the stream."""
        raise NotImplementedError("you must override me")

    @staticmethod
    def dump(item: Any, filepath: str) -> None:
        """Serialize to disk"""
        raise NotImplementedError("you must override me")

    @staticmethod
    def load(filepath: str) -> Any:
        """Deserialize from disk"""
        raise NotImplementedError("you must override me")
