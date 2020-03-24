# Copyright 2020-present Kensho Technologies, LLC.
from io import BytesIO as BinaryStreamImpl, UnsupportedOperation
import unittest

from ..verifiable_stream import VerifiableStream, verify_stream


class TestVerifiableStream(unittest.TestCase):
    def test_verification(self):
        stream = VerifiableStream()

        stream.write(b"foobar")
        nonce, hmac_code = stream.finalize()

        # Ensure verification on the stream itself works fine.
        verify_stream(nonce, hmac_code, stream)

        # Ensure no rewinding of the stream is necessary for verification.
        verify_stream(nonce, hmac_code, stream)

        other_stream = BinaryStreamImpl(b"not foobar")
        with self.assertRaisesRegex(AssertionError, "HMACs did not match.*"):
            verify_stream(nonce, hmac_code, other_stream)

    def test_attributes_raising_errors(self):
        stream = VerifiableStream()

        with self.assertRaises(AttributeError):
            stream.non_existent_attr

        with self.assertRaises(AssertionError):
            stream.name()

        with self.assertRaises(AssertionError):
            stream.mode()

        with self.assertRaises(UnsupportedOperation):
            stream.fileno()

    def test_dummy_and_passthrough_methods(self):
        stream = VerifiableStream()
        stream.write(b"these are some bytes")
        self.assertFalse(stream.closed)

        for attr in ("flush", "readable", "writable", "seekable"):
            getattr(stream, attr)()  # none of them should raise error

    def test_context_managers(self):
        msg = b"these are some btyes"
        stream = VerifiableStream()
        with stream as s:
            s.write(msg)
            nonce, hmac_code = stream.finalize()
            # Ensure verification on the stream itself works fine.
            verify_stream(nonce, hmac_code, s)
            recovered_msg = s.read()
            self.assertEqual(msg, recovered_msg)

        # make sure stream remains finalized
        self.assertTrue(stream._finalized)
        with self.assertRaises(AssertionError):
            stream.write(msg)

        # make sure we can still read
        with self.assertRaises(ValueError):
            stream.seek(0)  # should be closed

    def test_cannot_write_after_finalizing(self):
        stream = VerifiableStream()

        stream.write(b"foobar")
        stream.finalize()

        with self.assertRaises(AssertionError):
            stream.write(b"should not be able to write this")

    def test_cannot_seek_or_read_before_finalizing(self):
        stream = VerifiableStream()

        stream.write(b"foobar")

        with self.assertRaises(AssertionError):
            stream.seek(0)

        with self.assertRaises(AssertionError):
            stream.read()

    def test_read_and_write_output(self):
        items = [b"a", b"asdf", b"", b"cool beans"]
        for item in items:
            stream = VerifiableStream()
            result = stream.write(item)
            stream.finalize()
            stream.seek(0)
            replayed = stream.read()
            self.assertEqual(result, len(item))
            self.assertEqual(item, replayed)
