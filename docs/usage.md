# Creating a Serializable Model
In order to take advantage of the consistent API for loading and saving models,
your model must inherit from an abstract class called `SerializableModel`.
This is necessary for `special_k` to know how to serialize your model.
A few ["base" serializers](../special_k/serializers/base_serializers.py) ship with the package,
including JSON, MessagePack, pickle, dill, joblib, and Keras.
You can also [define your own serializers](./advanced_usage.md#registering-a-custom-serializer) if necessary.
For each attribute of your model, you will need to specify which serializer to use for it.

You must also implement a validation function that ensures your model works as anticipated
(or else raises or logs an error, or performs another behavior that you define).
Because the environment into which a model is loaded may not match the environment in which it was serialized,
this post-deserialization validation is important and useful for ensuring the statistical safety of your model.
Please see ["Why use `special_k`"](./overview.md#ensuring-statistical-safety) for more information on this topic.

One of the best ways to check that your model is working properly is to serialize a small amount of data
and the model's predictions on those data along with the model.
The validation code can then make predictions on the input data and check that the predictions match the serialized outputs.

Last, you must implement the `predict` function, which takes in inputs of your choice and returns a prediction.

An example is as follows:
```python
from typing import Any, Dict, Tuple

from keras.models import Model
from special_k import SerializableModel


class ExampleTextClassifier(SerializableModel):
    def __init__(self, preprocessor: Any, classifier: Model, validation_data: Dict[str, Any]):
        super().__init__()
        # Preprocessor is a generic Python object that does some preprocessing,
        # e.g. string normalization or integer encoding
        self.preprocessor = preprocessor
        # Classifier is a Keras model that classifies preprocessed text.
        self.classifier = classifier
        # Validation data maps example input data to expected outputs
        self.validation_data = validation_data

    @property
    def _name(self) -> str:
        """(Required) Return the name of the model"""
        return "World's ok-est text classfier"

    @property
    def custom_serialization(self) -> Dict[str, Tuple[str]]:
        """(Required) Describe how this model should be serialized
        
        Return a mapping of model attributes to tuples containing the serializer for that attribute
        and the name of the file to serialize that attribute to.
        """
        return {
            # Serialize the preprocessor attribute using pickle, and write the result to `preprocessor.pkl`.
            "preprocessor": ("pickle", "preprocessor.pkl"),
            # Serialize the classifier attribute using the keras serializer, and write the result to `classifier.h5`.
            "classifier": ("keras", "classifier.h5"),
            # Serialize validation data with JSON and write the result to `validation_data.json`.
            "validation_data": ("json", "validation_data.json"),
        }

    def validate_model(self) -> None:
        """"(Required) Validate that the model is working properly"""
        for input_datum, expected_output in self.validation_data.items():
            prediction = self.predict(input_datum)
            if prediction != expected_output:
                raise AssertionError("Model prediction did not match expected output")

    def predict(self, text) -> Any:
        """(Required) Use inputs of your choice to make a prediction"""
        preprocessed_text = self.preprocessor.run(text)
        return self.classifier.predict(preprocessed_text)

    def post_deserialization_hook(self) -> None:
        """(Optional) Any custom logic you would like to call after deserialization"""
        self.model._make_predict_function()  # needed to make keras threadsafe
```

# Serializing and Deserializing Models
Any model that subclasses `SerializableModel` and implements the required methods can be easily saved and loaded with the `special_k` API.
For an explanation of how serialization and deserialization work, including cryptographic validation of serialized models,
please see ["How Does `special_k` Work?"](./overview.md#How-does-special-k-work?)

## Serializing Models
To save a model to a tar file use
```python
from special_k import save_model_to_tarball

model = MyModel()
save_model_to_tarball(
    model=model,  # something of type SerializableModel
    tarball_path="model.tar.gz",  # where to save serialized model
    gpg_home_dir="~/.gnupg",  # gpg home directory with signing key
    signing_key_fingerprint="32317E2770B751C5AEC07BCF5701FB37EED66CA4",  # fingerprint of signing key
    passphrase="test",  # passphrase to unlock signing key
)
```

You can also save a model to a tarball stream:
```python
from special_k import save_model_to_tarball_stream

# Note: stream is not rewound to the beginning
stream = save_model_to_tarball_stream(model, gpg_home_dir, signing_key_fingerprint, passphrase)
```

Please note that serializing a model in this way will render the `model` object unusable.
To use the model after serialization, you should reload it from the tarball or tarball stream.

## Deserializing Models
Deserializing models is even simpler than serializing them!

```python
from special_k import load_model_from_tarball, load_model_from_tarball_stream

# Load a SerializableModel from a tarball...
model = load_model_from_tarball(tarball_path)

# ...or a tarball stream
model = load_model_from_tarball_stream(tarball_stream)
```
