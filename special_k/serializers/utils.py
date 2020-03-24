# Copyright 2020-present Kensho Technologies, LLC.
import codecs
import contextlib
import json
import os
import shutil
import tempfile
from typing import Any, Callable
from uuid import uuid4

import h5py

from .base import STREAM_TYPE


def write_json_to_stream(item: Any, stream: STREAM_TYPE) -> int:  # stream.write returns an int
    """Write json to a stream with the right encoding"""
    return stream.write(json.dumps(item).encode("utf-8"))


def read_json_from_stream(stream: STREAM_TYPE) -> Any:
    """Read json from a stream with the right encoding"""
    return json.loads(stream.read().decode("utf-8"))


def serialize_to_temp_h5py(item: Any, stream: STREAM_TYPE, save_func: Callable) -> None:
    """Serialize `item` to a stream

    This is a hack to avoid writing files to disk!
    This will
        create an h5py file in memory
        write the contents of the h5py object into `stream`

    Args:
        item: item to serialize
        stream: stream into which to serialize the object
        save_func: function to dump `item` to h5py
    """
    fake_name = "fake name does not matter"
    with h5py.File(fake_name, driver="core", backing_store=False) as h5file:
        save_func(item, h5file)
        h5file.flush()
        stream.write(h5file.fid.get_file_image())
    if os.path.exists(fake_name):
        raise AssertionError(
            "This should never happen. A fake file named {} was created "
            "in memory but buggy code accidentally wrote it to "
            "disk".format(fake_name)
        )


def deserialize_from_temp_h5py(stream: STREAM_TYPE, load_func: Callable) -> Any:
    """Deserialize from a stream

    This is a hack to avoid writing files to disk!
    A fake h5py file is created and all of the attributes are manually set to correct values.
    Change this code with great care!!

    Args:
        stream: a stream-like object from which to read an object
        load_func: function to load `item` from h5py

    Returns:
        Whatever was serialized as an h5py file to `stream`.
    """
    file_access_property_list = h5py.h5p.create(h5py.h5p.FILE_ACCESS)
    file_access_property_list.set_fapl_core(backing_store=False)
    file_access_property_list.set_file_image(stream.read())

    file_id_args = {
        "fapl": file_access_property_list,
        "flags": h5py.h5f.ACC_RDONLY,
        "name": b"this should never matter",
    }

    h5_file_args = {"backing_store": False, "driver": "core", "mode": "r"}

    with contextlib.closing(h5py.h5f.open(**file_id_args)) as file_id:
        with h5py.File(file_id, **h5_file_args) as h5_file:
            if os.path.exists(file_id_args["name"]):
                raise AssertionError(
                    "Buggy code- this should never happen. "
                    "File {} was written to disk even though you "
                    "really did not want to.".format(file_id_args["name"])
                )
            return load_func(h5_file)


def serialize_to_temp_file(item: Any, stream: STREAM_TYPE, save_func: Callable) -> None:
    """Serialize `item` to a stream

    We serialize to a temporary file, then read that file into the stream.

    Args:
        item: item to serialize
        stream: stream into which to serialize the object
        save_func: function to dump `item` to a temp file
    """
    temp_dir = tempfile.mkdtemp()

    try:
        temp_file_name = str(uuid4()).replace("-", "")
        absolute_file_path = os.path.join(temp_dir, temp_file_name)
        save_func(item, absolute_file_path)

        # While we wrote the file to disk and closed it, the file system does not necessarily
        # guarantee that the file is already visible within its directory. For this guarantee,
        # we have to open and fsync the directory before attempting to open the file itself.
        dirfd = os.open(temp_dir, os.O_DIRECTORY)
        os.fsync(dirfd)
        os.close(dirfd)

        # Now we can open and read the file into the stream.
        with codecs.open(absolute_file_path, "rb") as f:
            while True:
                buf = f.read(4096)
                if not buf:
                    break
                stream.write(buf)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def deserialize_from_temp_file(stream: STREAM_TYPE, load_func: Callable) -> Any:
    """Deserialize from a stream

    We write the stream to a temporary file, then read the file with `load_func`.

    Args:
        stream: a stream-like object from which to read an object
        load_func: function to load `item` from h5py

    Returns:
        Whatever was serialized to the temp file in `stream`
    """
    temp_dir = tempfile.mkdtemp()

    try:
        temp_file_name = str(uuid4()).replace("-", "")
        absolute_file_path = os.path.join(temp_dir, temp_file_name)

        with codecs.open(absolute_file_path, "wb") as f:
            while True:
                buf = stream.read(4096)
                if not buf:
                    break
                f.write(buf)

            # Ensure the file's data is actually saved and visible.
            f.flush()
            os.fsync(f.fileno())

        # While we wrote the file to disk and closed it, the file system does not necessarily
        # guarantee that the file is already visible within its directory. For this guarantee,
        # we have to open and fsync the directory before attempting to open the file itself.
        dirfd = os.open(temp_dir, os.O_DIRECTORY)
        os.fsync(dirfd)
        os.close(dirfd)

        # read file with `load_func` and return it
        return load_func(absolute_file_path)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
