# Copyright 2020-present Kensho Technologies, LLC.
"""Define a model interface that ensures the model may be saved together with its attributes."""
from abc import ABCMeta, abstractmethod
import logging

from voluptuous import Any, Schema

from . import model_interface
from .serializers import REGISTRY
from .utils import NON_EMPTY_STRING, filename_safe_string


logger = logging.getLogger(__name__)


class CustomSerializedValue(object):
    """Placeholder object for values that are saved using custom serialization.

    When serializing a SerializableModel, we proceed as follows:
    - Serialize all the attributes that are registered for custom serialization.
    - Set all such attributes' values to instances of CustomSerializedValue, so that they are known
      to be dead, transient values. This helps with debugging, since this type is not used for
      anything else.
    - Serialize the model itself, with the transient CustomSerializedValue() objects in place of
      the data that required custom serialization.

    Then, when deserializing, we follow the steps in reverse:
    - Deserialize the model itself, getting instances of CustomSerializedValue() as the values of
      all attributes that use custom serialization.
    - Deserialize such attributes' actual values, and set them on the model thereby replacing
      the placeholders with the real data.
    """


class SerializableModel(model_interface.ModelInterface, metaclass=ABCMeta):
    def __init__(self):
        """Construct a new SerializableModel object."""
        super(SerializableModel, self).__init__()

        # Verify that the custom serialization for the model is correct. This is done here to make
        # sure that you cannot instantiate a bad serializable model
        # The validator `custom_serialization_validator` is made here and not as a global constant
        # to make the code not care about when new serializers are registered with the registry.
        # WARNING: it is possible to screw yourself by making a serializable model, and then
        # messing with the REGISTRY.
        nontrivial_serializer = Schema((Any(*REGISTRY.available_serializers), filename_safe_string))
        serializer_validator = Any(nontrivial_serializer, (None, None))
        custom_serialization_validator = Schema({NON_EMPTY_STRING: serializer_validator})
        custom_serialization_validator(self.custom_serialization)

    @property
    @abstractmethod
    def custom_serialization(self):
        """Return a description of which attributes to serialize and how.

        Returns a dict attr_name -> (serializer name, file name).
        The dict may be empty, if no attributes require custom serialization.

        ***FOR TESTING PURPOSES ONLY*** the value `None` is also allowed,
        and indicates that the model is not able to be serialized at all.
        """
        raise NotImplementedError("Subclasses should implement this property.")

    def post_deserialization_hook(self):
        """Any custom magic that is needed after deserialization can be called here"""
