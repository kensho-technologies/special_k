# Copyright 2020-present Kensho Technologies, LLC.
import base64
import hashlib
import hmac
from io import BytesIO
import os
from types import TracebackType
from typing import BinaryIO, Iterable, List, Optional, Type

from voluptuous import validate


HASHER = hashlib.sha256
ENCODING = "utf-8"


@validate(bstring=bytes)
def _convert_base64_bytes_to_string(bstring):
    """Convert a bytestring wtih base64 to unicode."""
    return base64.b64encode(bstring).decode(ENCODING)


@validate(text_string=str)
def _convert_string_to_base64_bytes(text_string):
    """Convert a unicode string to base64 bytestring"""
    return base64.b64decode(text_string.encode(ENCODING))


def verify_stream(nonce, expected_hmac, stream):
    """Verify that the contents of the stream match its HMAC, or raise an error.

    Args:
        nonce: string, the random nonce returned by the VerifiableStream.finalize() method
               WARNING, this is not the self._random_nonce, it is string encoded
        expected_hmac: string, the hex HMAC code returned by the VerifiableStream.finalize() method
        stream: file-like stream, the stream to verify against its nonce and HMAC.
                Does not have to be an instance of VerifiableStream!

    Raises:
        AssertionError, if the HMAC did not match the stream's data
    """
    stream.seek(0)  # Rewind the stream to its start, can't verify just a piece of it.
    hmac_state = hmac.new(_convert_string_to_base64_bytes(nonce), digestmod=HASHER)

    while True:
        data = stream.read(4096)
        if not data:
            break
        hmac_state.update(data)

    # Rewind the stream again for convenience, since assuming it passes verification,
    # it's about to get read again to serve its actual purpose.
    stream.seek(0)

    calculated_hmac_bytes = hmac_state.digest()  # bytes!
    expected_hmac_bytes = _convert_string_to_base64_bytes(expected_hmac)
    if not hmac.compare_digest(expected_hmac_bytes, calculated_hmac_bytes):
        calculated_hmac_string = _convert_base64_bytes_to_string(calculated_hmac_bytes)
        raise AssertionError(
            "HMACs did not match, this should not ever happen: {} {}".format(
                expected_hmac, calculated_hmac_string
            )
        )


class VerifiableStream(BinaryIO):
    """A binary stream whose contents can be verified to not have changed.

    The stream does not accept a HMAC key, but generates it randomly as a nonce. While unusual,
    this is intentional -- these streams are meant to be used as part of model serialization,
    where their nonces and HMAC codes are stored in a cryptographically signed metadata file.
    In other words, the HMAC simply ensures that stream's data has not changed, and does not
    guarantee the data's origin -- that's the metadata signature's job.

    The stream is meant to be used in the following sequence:
        - instantiate the stream
        - write all data to the stream (the stream is not readable yet!)
        - call "finalize()" on the stream, saving the returned nonce and HMAC code
        - read data from the stream (the stream is not writable any more!)
    """

    def __init__(self):
        """Create a new VerifiableStream with a random nonce."""
        self._finalized = False
        self._random_nonce = os.urandom(16)  # this is bytes, be careful trying to add strings to it
        self._underlying_stream = BytesIO()
        self._hmac_state = hmac.new(self._random_nonce, digestmod=HASHER)

    def _ensure_finalized(self):
        """Raise an error if the stream has not already been finalized."""
        if not self._finalized:
            raise AssertionError("Expected the stream to be finalized, but it was not!")

    def _ensure_not_finalized(self):
        """Raise an error if the stream has already been finalized."""
        if self._finalized:
            raise AssertionError("Expected the stream to not be finalized, but it was!")

    def finalize(self):
        """Calculate the HMAC code for the stream, disable writing and enable reading.

        Returns:
            tuple (nonce, HMAC code)  (both of type string)
        """
        self._ensure_not_finalized()

        self._finalized = True

        nonce_string = _convert_base64_bytes_to_string(self._random_nonce)
        hmac_string = _convert_base64_bytes_to_string(self._hmac_state.digest())

        return nonce_string, hmac_string

    # methods for writing require that the stream not be finalized
    def writable(self) -> bool:
        """Return True if the stream is writable, and False otherwise."""
        if self._finalized:
            return False
        else:
            return self._underlying_stream.writable()

    @validate(b=bytes)
    def write(self, b: bytes) -> int:
        """Write the given binary data to the stream, and include it in the HMAC calculation."""
        self._ensure_not_finalized()
        num_bytes = self._underlying_stream.write(b)
        self._hmac_state.update(b)
        return num_bytes

    def writelines(self, lines: Iterable[bytes]) -> None:
        """Write lines to a stream"""
        self._ensure_not_finalized()  # technically done by `write` but doesn't hurt to be safe
        for line in lines:
            self.write(line)
        return None

    # methods for reading require that the stream is finalized
    def readable(self) -> bool:
        """Return True if the stream is readable, and False otherwise."""
        if self._finalized:
            return self._underlying_stream.readable()
        else:
            return False

    def read(self, size=None) -> bytes:
        """Read bytes from stream"""
        self._ensure_finalized()
        return self._underlying_stream.read(size)

    def readall(self) -> bytes:
        """Read lines from stream"""
        raise NotImplementedError(
            "`VerifiablStream` does not implement `readall` since the underlying BtytesIO does not "
            "implement it."
        )

    def readline(self, size=None) -> bytes:
        """Read a line from stream"""
        self._ensure_finalized()
        return self._underlying_stream.readline(size)

    def readlines(self, size=None) -> List[bytes]:
        """Read lines from stream"""
        self._ensure_finalized()
        return self._underlying_stream.readlines(size)

    def read1(self, size) -> bytes:
        """Read bytes from stream"""
        self._ensure_finalized()
        return self._underlying_stream.read1(size)

    def readinto(self, b) -> Optional[int]:
        """Read bytes into another buffer"""
        self._ensure_finalized()
        return self._underlying_stream.readinto(b)

    def readinto1(self, b) -> Optional[int]:
        """Read bytes into another buffer"""
        self._ensure_finalized()
        return self._underlying_stream.readinto1(b)

    # seeking requires a finalized stream
    def seekable(self):
        """Return True if the read pointer in the stream can be moved, and False otherwise."""
        if self._finalized:
            return self._underlying_stream.seekable()
        else:
            return False

    def seek(self, *args, **kwargs) -> int:
        """Seek to a new position. Return the new position"""
        self._ensure_finalized()
        return self._underlying_stream.seek(*args, **kwargs)

    def truncate(self, size: Optional[int] = ...) -> None:
        """Truncate the stream"""
        raise NotImplementedError(
            "`VerifiableStream` does not support truncation. It is too "
            "complicated to keep track of the hmac digests"
        )

    def close(self):
        """Close the stream, discarding its data. Will raise an error if not finalized yet."""
        if self._finalized:
            return self._underlying_stream.close()
        else:
            raise AssertionError(
                "Attempting to close an unfinalized VerifiableStream. This is "
                "almost certainly a bug."
            )

    # a bunch of attributes/methods that are always accessible
    def isatty(self) -> bool:
        """Determine whether this is a terminal"""
        return self._underlying_stream.isatty()

    @property
    def closed(self) -> bool:
        """Determine whether the stream is closed"""
        return self._underlying_stream.closed

    def fileno(self) -> int:
        """Return the underlying file descriptor"""
        # this will technically raise UnsuportedOperation, but better to let BytesIO do that
        return self._underlying_stream.fileno()

    def mode(self) -> str:
        """Return the underlying file descriptor"""
        # this doesn't exist for the underlying stream
        raise AssertionError(
            "`VerifiableStream` does not have a mode. This is probably a bug in "
            "something assuming that the stream is a backed by a file"
        )

    def name(self) -> str:
        """Return the underlying file descriptor"""
        # this doesn't exist for the underlying stream
        raise AssertionError(
            "`VerifiableStream` does not have a name. This is probably a bug in "
            "something assuming the stream is a file descriptor"
        )

    def flush(self) -> None:
        """Flush the underlying stream"""
        # this technically does nothing in BytesIO
        return self._underlying_stream.flush()

    def tell(self) -> int:
        """Tell the current position"""
        return self._underlying_stream.tell()

    # context manager methods
    def __enter__(self) -> "VerifiableStream":
        """Enter"""
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> bool:
        """Exit"""
        return self._underlying_stream.__exit__(exc_type, exc_val, exc_tb)
