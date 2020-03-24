# Registering a Custom Serializer
The package ships with a lot of [built-in serializers](../special_k/serializers/base_serializers.py),
which should be sufficient for most use cases. However, you may find the need to write a custom serializer.
There are two steps:
1. Define the serializer. It should inherit from `serializers.base.BaseIO` and implement
two methods: `_serialize_to_stream` and `_deserialize_from_stream`.
2. Register the serializer in the registry in `serializers.registry.REGISTRY`.

You can then create a SerializableModel with an attribute serialized by your custom serializer,
as specified in the model's `custom_serialization` property.

Example:
```python
# step 1
from io import BytesIO
from typing import Any

from special_k.serializers.base import BaseIO

class CoolSerializerIO(BaseIO):
    @staticmethod
    def _serialize_to_stream(item: Any, stream: BytesIO) -> None:
        """Serialize to a stream"""
        write_stuff_to_stream(item, stream)  # your code here

    @staticmethod
    def _deserialize_from_stream(stream: BytesIO) -> Any:
        """De-serialize from a stream"""
        return read_stuff_from_stream(stream)  # your code here


# step 2
from special_k.serializers.registry import REGISTRY


# List available serializers, as a mapping from serializer name to subclass of BaseIO
print(REGISTRY.available_serializers)
# Register your custom serializer
REGISTRY.register_serializer('cool-and-unique-name-for-serializer', CoolSerializerIO)
```

# Checking GPG Key Expiration
To check expirations of your GPG keys after installing `special_k`, run `python -m special_k.check_gpg_keys`.
To configure the number of days you would like to be warned before a key expires, pass the argument `days_before_warning`.
The following snippet can be used to obtain key expiry information within a python script:
```python
from special_k import check_gpg_key_expiry

no_keys_close_to_expiry = check_gpg_key_expiry(days_warning_for_key_expiration=30)
```
