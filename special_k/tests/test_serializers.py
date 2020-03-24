# Copyright 2020-present Kensho Technologies, LLC.
from io import BytesIO as BinaryStreamImpl
import unittest

import numpy as np
from numpy.testing import assert_allclose
from tensorflow.keras import losses, metrics, optimizers
from tensorflow.keras.layers import Dense, Input
from tensorflow.keras.models import Model

import torch

from . import SERIALIZES_JSON_DICTS
from ..serializers.base_serializers import (
    JoblibIO,
    KerasCustomComponent,
    KerasCustomObjectsIO,
    KerasIO,
    TorchModelIO,
    TorchStateDictIO,
)


NONCE_ADDITION = "123"
HMAC_ADDITION = "123"


class CustomKerasLayer(Dense):
    useless_attribute = "foo"


class Net(torch.nn.Module):
    def __init__(self, dimension_in, dimension_out):
        super(Net, self).__init__()
        self.linear = torch.nn.Linear(dimension_in, dimension_out)
        self.relu = torch.nn.ReLU()

    def forward(self, x):
        o = self.linear(x)
        return self.relu(o)


class TestSerializers(unittest.TestCase):
    def _corrupted_stream_helper(self, serializer, payload):
        stream, nonce, hmac_code = serializer.to_verifiable_stream(payload)
        stream.seek(0)
        corrupted_stream = BinaryStreamImpl()
        corrupted_stream.write(stream.read())
        corrupted_stream.write(b"corruption")
        with self.assertRaisesRegex(AssertionError, "HMACs did not match.*"):
            serializer.from_verifiable_stream(corrupted_stream, nonce, hmac_code)

        # Intentionally corrupt the nonce and hmac_code.
        # Deserialization should fail both times.
        with self.assertRaisesRegex(AssertionError, "HMACs did not match.*"):
            serializer.from_verifiable_stream(corrupted_stream, nonce + NONCE_ADDITION, hmac_code)
        with self.assertRaisesRegex(AssertionError, "HMACs did not match.*"):
            serializer.from_verifiable_stream(corrupted_stream, nonce, hmac_code + HMAC_ADDITION)

    def _compare_serializer_output(self, serializer, payload, compare_fn=None):
        stream, nonce, hmac_code = serializer.to_verifiable_stream(payload)

        # Make sure the API contract with nonce and hmac being strings is unchanged
        self.assertIsInstance(nonce, str)
        self.assertIsInstance(hmac_code, str)

        # run deserialization twice without rewinding the stream to make sure we dont need to
        # rewind streams
        for _ in range(2):
            deserialized_payload = serializer.from_verifiable_stream(stream, nonce, hmac_code)
            if compare_fn is None:
                self.assertEqual(payload, deserialized_payload)
            else:
                compare_fn(payload, deserialized_payload)

    def test_verifiable_stream_serialization(self):
        payload = {
            "abc": [1, 2, 3],
            "def": 3.14159,
            "foo": "bar",
            "nested": {"dicts": "are", "sometimes": "hard"},
        }

        for serializer in SERIALIZES_JSON_DICTS:
            self._compare_serializer_output(serializer, payload)
            self._corrupted_stream_helper(serializer, payload)

    def test_numpy_joblib_serialization(self):
        def compare_fn(original, deserialized):
            self.assertTrue(np.all(original == deserialized))

        for dtype in (np.int, np.float, bool):
            payload = np.ones((10, 4), dtype=dtype)
            self._compare_serializer_output(JoblibIO, payload, compare_fn=compare_fn)
            self._corrupted_stream_helper(JoblibIO, payload)

    def test_keras_model_serialization(self):
        # create an `item`

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

        def compare_fn(original, deserialized):
            actual_output = deserialized.predict(x)
            expected_output = original.predict(x)
            assert_allclose(actual_output, expected_output, atol=1e-05)

        self._compare_serializer_output(KerasIO, model, compare_fn=compare_fn)
        self._corrupted_stream_helper(KerasIO, model)

    def test_custom_keras_model_serialization(self):
        # create an `item`
        inputs = Input(shape=(3,))
        x = CustomKerasLayer(2)(inputs)
        outputs = Dense(3)(x)

        model = Model(inputs, outputs)
        model.compile(
            loss=losses.MSE, optimizer=optimizers.Adam(), metrics=[metrics.categorical_accuracy]
        )

        x = np.array([[1, 2, 3]])
        y = np.array([[2, 3, 4]])
        model.train_on_batch(x, y)

        custom_serializable_model = KerasCustomComponent(model, {})

        # first, test that we can serialize, but not deserialize without the custom objects
        stream, nonce, hmac_code = KerasCustomObjectsIO.to_verifiable_stream(
            custom_serializable_model
        )
        with self.assertRaisesRegex(ValueError, "Unknown layer.*"):
            KerasCustomObjectsIO.from_verifiable_stream(stream, nonce, hmac_code)

        # set bad types as the CUSTOM_OBJECT_ATTR_NAME
        for bad_val in ("a string", ["a", "list"], 1, 1.5):
            custom_serializable_model = KerasCustomComponent(model, bad_val)
            with self.assertRaises(TypeError):
                KerasCustomObjectsIO.to_verifiable_stream(custom_serializable_model)

        # dict with bad keys raises ValueError
        custom_serializable_model = KerasCustomComponent(model, {"a": 1, 2: 3})
        with self.assertRaises(ValueError):
            KerasCustomObjectsIO.to_verifiable_stream(custom_serializable_model)

        # now set the attribute properly
        correct_custom_objects = {"CustomKerasLayer": CustomKerasLayer}
        custom_serializable_model = KerasCustomComponent(model, correct_custom_objects)

        # now the usual tests: model output matches deserialized model output
        # and hmac / nonce corruption raise errors
        def compare_fn(original, deserialized):
            # first check custom objects
            self.assertEqual(original.custom_objects, deserialized.custom_objects)
            # then check model output
            actual_output = deserialized.keras_model.predict(x)
            expected_output = original.keras_model.predict(x)
            assert_allclose(actual_output, expected_output, atol=1e-05)

        self._compare_serializer_output(
            KerasCustomObjectsIO, custom_serializable_model, compare_fn=compare_fn
        )
        self._corrupted_stream_helper(KerasCustomObjectsIO, custom_serializable_model)

    @staticmethod
    def _get_trained_torch_model(dimension_in, dimension_out):
        steps = 4
        N = 64

        model = Net(dimension_in, dimension_out)

        x = torch.randn(N, dimension_in)
        y = torch.randn(N, dimension_out)

        criterion = torch.nn.MSELoss(reduction="sum")
        optimizer = torch.optim.SGD(model.parameters(), lr=1e-4)

        for _ in range(steps):
            # Forward pass: Compute predicted y by passing x to the model
            y_pred = model(x)
            loss = criterion(y_pred, y)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        return model

    def test_torch_model_io(self):
        dimension_in = 20
        dimension_out = 3
        model = self._get_trained_torch_model(dimension_in, dimension_out)
        x = torch.randn(10, dimension_in)

        def compare_fn(original, deserialized):
            actual_output = deserialized(x).detach()
            expected_output = original(x).detach()
            assert_allclose(actual_output, expected_output, atol=1e-05)

        self._compare_serializer_output(TorchModelIO, model, compare_fn=compare_fn)
        self._corrupted_stream_helper(TorchModelIO, model)

    def test_torch_state_dict_io(self):
        dimension_in = 20
        dimension_out = 3
        model = self._get_trained_torch_model(dimension_in, dimension_out)
        x = torch.randn(10, dimension_in)

        def compare_fn(original, deserialized):
            original_model = Net(dimension_in, dimension_out)
            original_model.load_state_dict(original)

            deserialized_model = Net(dimension_in, dimension_out)
            deserialized_model.load_state_dict(deserialized)

            actual_output = deserialized_model(x).detach()
            expected_output = original_model(x).detach()
            assert_allclose(actual_output, expected_output, atol=1e-05)

        self._compare_serializer_output(TorchStateDictIO, model.state_dict(), compare_fn=compare_fn)
        self._corrupted_stream_helper(TorchStateDictIO, model.state_dict())
