# Copyright 2020-present Kensho Technologies, LLC.
"""Define an abstract model interface from which all serializable models must inherit."""
from abc import ABCMeta, abstractmethod
import logging


logger = logging.getLogger(__name__)


class ModelInterface(metaclass=ABCMeta):
    """The interface that all model objects must obey."""

    _metadata = None  # changing this line will have bad consequences :(

    @property
    def _name(self):
        """Internal model name"""
        raise NotImplementedError("You must give your model a name")

    @property
    def model_name(self):
        """Nice human-readable model name"""
        return self._name

    @property
    def metadata(self):
        """A dictionary that contains meta information about the model.

        Some examples of relevant meta information include:
            - Description: Human readable description of the model.
            - Build environment: git-rev, server-identity, pip-freeze, OS, training time, etc.
            - Training configuration: learning-rate, estimator type, etc.
            - Information about the data (e.g., which features were used, which part of the data
                was used for training/which for validation)

        Since the meta information can be organized into different types of information,
        please take care into organizing it into appropriate namespaces.
        """
        return self._metadata

    @metadata.setter
    def metadata(self, value):
        """Setter for metadata if it hasn't been set before.

        Args:
            value: None or a dict
        """
        if value is not None and not isinstance(value, dict):
            raise TypeError('Metadata has to be a dictionary or None. Got "{}"'.format(type(value)))

        if self._metadata is None or self._metadata == {}:
            self._metadata = value
        else:
            # Model metadata should only be set during build time.
            # If one is attempting to mutate its value -- this is likely an abuse of logic.
            # We are going to disallow that. (There has to be a **really** good reason to
            # remove this else statement.)
            raise AssertionError(
                "Model meta data can only set once during build time. "
                "Current value {}, attempting to set to {}.".format(self._metadata, value)
            )

    @abstractmethod
    def predict(self, X):
        """Make a prediction for the given input data."""
        raise NotImplementedError("You must implement `predict`")

    @abstractmethod
    def validate_model(self):
        """Raise ModelValidationError when the model is invalid.

        In practice, usually used to check that the deserialized model predicts the same values as
        the model was predicting at train time (using train data serialized with the model).
        """
        raise NotImplementedError("You must implement `validate_model`")
