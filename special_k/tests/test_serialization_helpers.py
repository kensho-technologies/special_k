# Copyright 2020-present Kensho Technologies, LLC.
import hashlib
from io import BytesIO as BinaryStreamImpl
import os
import shutil
import tempfile
import unittest

import numpy as np
from numpy.testing import assert_allclose, assert_array_equal
import pandas as pd
from tensorflow.keras import losses, metrics, optimizers
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.models import Model

from . import SERIALIZES_JSON_DICTS
from ..serializers.base_serializers import KerasIO, PickleIO, get_base_serializer_map
from ..serializers.utils import (
    deserialize_from_temp_file,
    deserialize_from_temp_h5py,
    serialize_to_temp_file,
    serialize_to_temp_h5py,
)
from ..utils import hash_train_and_val_data, safe_pd_read_msgpack
from ..verifiable_stream import VerifiableStream, verify_stream


TEST_HMAC_KEY = "uncle leonard stands alone"


class TempDirTestCase(unittest.TestCase):
    """A class to make a directory for model contents and model files"""

    def _clear_dir(self):
        """clear the contents of model_contents_dir"""
        if os.path.exists(self.model_contents_dir):
            shutil.rmtree(self.model_contents_dir)
            os.makedirs(self.model_contents_dir)

    def setUp(self):
        # Create a temporary directory
        test_dir = tempfile.mkdtemp()
        self.test_dir = test_dir
        self.model_contents_dir = os.path.join(test_dir, "model_contents")
        os.makedirs(self.model_contents_dir)

    def tearDown(self):
        # Remove the directory after the test
        shutil.rmtree(self.test_dir)


class TestSerializers(TempDirTestCase):
    def test_serializers(self):
        # different types of things to serialize
        # importantly, all can be compared with unittest.TestCase.assertEqual
        items = [
            {char: i for i, char in enumerate(list("neldon"))},  # dict
            list("this string will become a list"),
            "thou shalt test thine code",  # str
        ]
        for ext, serializer in get_base_serializer_map().items():
            # KerasIO et al cannot serialize base types
            if serializer not in SERIALIZES_JSON_DICTS:
                continue
            for item in items:
                filename = "thing" + ext
                filepath = os.path.join(self.model_contents_dir, filename)
                serializer.dump(item, filepath)

                retrieved_item = serializer.load(filepath)
                self.assertEqual(item, retrieved_item)

    def test_safe_pd_read_msgpack(self):
        test_df = pd.DataFrame({"a": 1, "b": 2}, index=[0])
        exist_fpath = os.path.join(self.model_contents_dir, "temp_file.mp")
        non_exist_fpath = os.path.join(self.model_contents_dir, "test_safe_msgpack_non_exist.mp")
        test_df.to_msgpack(exist_fpath)
        fpath_df = safe_pd_read_msgpack(exist_fpath)
        pd.testing.assert_frame_equal(test_df, fpath_df)
        with self.assertRaises(FileNotFoundError):
            safe_pd_read_msgpack(non_exist_fpath)

    def test_keras_serializer(self):
        inputs = Input(shape=(3,))
        x = Dense(2)(inputs)
        outputs = Dense(3)(x)

        model = Model(inputs, outputs)
        model.compile(
            loss=losses.MSE, optimizer=optimizers.Adam(), metrics=[metrics.categorical_accuracy]
        )

        x = np.array([[1, 2, 3]])
        y = np.array([[2, 3, 4]])
        model.train_on_batch(x, y)

        expected_output = model.predict(x)

        filename = "thing.keras"
        filepath = os.path.join(self.model_contents_dir, filename)
        KerasIO.dump(model, filepath)

        # The model should have been loaded correctly.
        loaded_model = KerasIO.load(filepath)
        actual_output = loaded_model.predict(x)
        assert_allclose(actual_output, expected_output, atol=1e-05)


class TestSerializationHelpers(unittest.TestCase):
    def test_serialization_to_temp_h5py(self):
        # create items to serialize: list of arrays and str
        items = [
            [np.random.random(size=(100, 20))],
            [np.array([1, 2, 3, 4]).astype(int)],
            [np.array([1.2, 3.4, np.nan, 5.6, 6.7])],
            [np.array([1.2, 3.4, np.nan, 5.6, 6.7]), np.array([1.2, 4.5, 3.4, np.nan, 5.6, 6.7])],
            [np.array([1.2, 3.4, 6.7]), "tahdb", np.array([1.2, 4.5, 3.4, np.nan, 5.6, 6.7])],
        ]

        # define dump and load functions
        def save_func(item, h5file):
            """Save function to dump item to h5file object"""
            for idx, subitem in enumerate(item):
                if isinstance(subitem, np.ndarray):
                    h5file.create_dataset(str(idx), data=subitem)
                elif isinstance(subitem, str):
                    h5file.attrs[str(idx)] = subitem

        def load_func(h5file):
            """Load function to load item from h5file object"""
            item = {}
            for key in h5file.keys():
                # return values of the h5file[key] in np.array format
                item[key] = h5file[key][:]
            for key in h5file.attrs.keys():
                item[key] = h5file.attrs[key]
            return [item[str(idx)] for idx in range(len(item))]

        for item in items:
            stream = VerifiableStream()
            serialize_to_temp_h5py(item, stream, save_func)
            nonce, hmac_code = stream.finalize()

            verify_stream(nonce, hmac_code, stream)
            retrieved_item = deserialize_from_temp_h5py(stream, load_func)
            for array, retrieved_array in zip(item, retrieved_item):
                assert_array_equal(array, retrieved_array)

            # No rewinding of the stream is necessary for deserialization.
            verify_stream(nonce, hmac_code, stream)
            retrieved_item = deserialize_from_temp_h5py(stream, load_func)
            for array, retrieved_array in zip(item, retrieved_item):
                assert_array_equal(array, retrieved_array)

            stream.seek(0)
            corrupted_stream = BinaryStreamImpl()
            corrupted_stream.write(stream.read())
            corrupted_stream.write(b"corruption")
            with self.assertRaises(ValueError):
                deserialize_from_temp_h5py(corrupted_stream, load_func)

    def test_serialization_to_temp_file(self):
        # create items to serialize
        items = [
            {char: i for i, char in enumerate(list("dictionary for test"))},  # dict
            list("list for test"),  # list
            "string for test",  # unicode
        ]

        for item in items:
            stream = VerifiableStream()
            serialize_to_temp_file(item, stream, PickleIO.dump)
            nonce, hmac_code = stream.finalize()

            verify_stream(nonce, hmac_code, stream)
            retrieved_item = deserialize_from_temp_file(stream, PickleIO.load)
            self.assertEqual(item, retrieved_item)

            # No rewinding of the stream is necessary for deserialization.
            verify_stream(nonce, hmac_code, stream)
            retrieved_item = deserialize_from_temp_file(stream, PickleIO.load)
            self.assertEqual(item, retrieved_item)

            stream.seek(0)
            corrupted_stream = BinaryStreamImpl()
            corrupted_stream.write(stream.read())
            corrupted_stream.write(b"corruption")
            with self.assertRaisesRegex(EOFError, "Ran out of input*"):
                deserialize_from_temp_file(corrupted_stream, PickleIO.load)


class TestHashing(unittest.TestCase):
    def test_hashing_numpy_arrays(self):
        x_train = np.arange(0, 10).reshape((5, 2))
        y_train = np.ones(x_train.shape[0])

        x_val = np.arange(0, 10).reshape((5, 2))
        y_val = np.ones(x_val.shape[0])

        hash_dict = hash_train_and_val_data(x_train, y_train, x_val, y_val)
        expected_hash_dict = {
            "x_train": hashlib.sha256(x_train.tostring()).hexdigest(),
            "y_train": hashlib.sha256(y_train.tostring()).hexdigest(),
            "x_val": hashlib.sha256(x_val.tostring()).hexdigest(),
            "y_val": hashlib.sha256(y_val.tostring()).hexdigest(),
        }
        self.assertEqual(hash_dict, expected_hash_dict)

        x_train = [x_train, x_train]
        x_val = [x_val, x_val]
        x_train_hash = hashlib.sha256()
        for xtr in x_train:
            x_train_hash.update(xtr.tostring())
        x_train_hash = x_train_hash.hexdigest()

        x_val_hash = hashlib.sha256()
        for xv in x_val:
            x_val_hash.update(xv.tostring())
        x_val_hash = x_val_hash.hexdigest()

        expected_hash_dict = {
            "x_train": x_train_hash,
            "y_train": hashlib.sha256(y_train.tostring()).hexdigest(),
            "x_val": x_val_hash,
            "y_val": hashlib.sha256(y_val.tostring()).hexdigest(),
        }
        self.assertEqual(
            hash_train_and_val_data(x_train, y_train, x_val, y_val), expected_hash_dict
        )

        with self.assertRaises(TypeError):
            # this should be an int as the first argument, which is not allowed
            hash_train_and_val_data(x_train[0][0, 0], y_train, x_val, y_val)

        with self.assertRaises(TypeError):
            # this should be list of string as the first argument, which is not allowed
            hash_train_and_val_data("list of strings".split(), y_train, x_val, y_val)
