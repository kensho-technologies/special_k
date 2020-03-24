# Copyright 2020-present Kensho Technologies, LLC.
from datetime import datetime
from io import BytesIO
import json
import logging
import os
from tarfile import TarFile
from typing import Any, Dict, Optional, Set

import voluptuous
from voluptuous import All, Invalid, Schema, validate

from .. import __version__ as package_version
from ..exceptions import SerializationError
from ..serializable_model import CustomSerializedValue, SerializableModel
from ..serializers import REGISTRY
from ..serializers.base_serializers import SERIALIZER_PICKLE
from ..signing import sign_message, verify_and_extract_message
from ..utils import (
    NON_EMPTY_STRING,
    consume_stream_into_tarball,
    filename_safe_string,
    get_installed_packages,
    get_model_directory_name,
    open_readonly_tarball_file,
)


# if a serialization scheme (serializer, filename) is None, None, do not write to tarball
ATTRIBUTE_DO_NOT_SERIALIZE = (None, None)

METADATA_FILENAME = "meta.json.asc"  # now ascii format signed metadata
MODEL_SELF_SERIALIZER = SERIALIZER_PICKLE
MODEL_FILE_NAME = "THEMODEL.pickle"
# keys for metadata json
METADATA_KEY_MODEL = "model"
METADATA_KEY_VERSION = "version"
METADATA_KEY_ATTRIBUTES = "attributes"
METADATA_KEY_PACKAGE_VERSION = "serializing_package_version"
METADATA_KEY_SERIALIZATION_DATE = "written_on_date"
METADATA_KEY_INSTALLED_PACKAGES = "installed_packages"

logger = logging.getLogger(__name__)


def stream_descriptor(pickle_only: bool = False) -> Schema:
    """Produce a validator for stream descriptors, optionally allowing only pickled format."""
    if pickle_only:
        serializer_validator = voluptuous.Any(SERIALIZER_PICKLE)
    else:
        # Here we will NOT check that the serializer is in the REGISTRY. This will avoid order
        # issues that arise when we care whether this module is imported before or after custom
        # serializers are registered. So we choose non_empty string, and validate at runtime
        # (i.e. in save/load to tarball) that the serializer is present
        serializer_validator = NON_EMPTY_STRING

    return Schema(
        {
            "filename": filename_safe_string,
            "nonce": NON_EMPTY_STRING,
            "hmac_code": NON_EMPTY_STRING,
            "serializer": serializer_validator,
        },
        required=True,
    )


attribute_descriptor = Schema(
    {NON_EMPTY_STRING: stream_descriptor(pickle_only=False)}, required=False
)
stream_type = Dict[str, str]

metadata_format = Schema(
    {
        # The "enum_of(3)" below means the version must be exactly 3.
        # This is how we ensure that tampering with the meta.version file is unproductive.
        # We can't be forced to interpret meta.json as any other version
        # since this value won't match.
        METADATA_KEY_VERSION: voluptuous.Any(3),
        METADATA_KEY_ATTRIBUTES: attribute_descriptor,
        METADATA_KEY_MODEL: stream_descriptor(pickle_only=True),
        METADATA_KEY_PACKAGE_VERSION: str,
        METADATA_KEY_SERIALIZATION_DATE: str,
        METADATA_KEY_INSTALLED_PACKAGES: voluptuous.Optional([All(str)]),
    },
    required=True,
)
metadata_type = Dict[str, Any]


def _load_item_from_tarfile_and_stream_data(
    tar_file: TarFile, model_directory: str, stream_data: dict
) -> Any:
    """Load a single item from a tarfile and verify"""
    logger.info("Loading file {}".format(stream_data["filename"]))
    item_path = os.path.join(model_directory, stream_data["filename"])
    serializer = REGISTRY.get_serializer_by_name(stream_data["serializer"])
    with open_readonly_tarball_file(tar_file, item_path) as fi:
        return serializer.from_verifiable_stream(fi, stream_data["nonce"], stream_data["hmac_code"])


def _check_and_raise_for_missing_or_null_serializer(needed_serializers: Set) -> None:
    """Check that all needed_serializers are present and raise if they are not"""
    if None in needed_serializers:
        raise ValueError(
            "Found `None` in set of needed serializers. "
            "This should never happen since `None` as a serializer should only occur "
            "with `None` and a filename, which would be ignored. A models's "
            "`custom_serialzation` property likely changed between serializing and "
            "deserializing the model."
        )

    missing_serializers = needed_serializers.difference(REGISTRY.available_serializers)
    if missing_serializers:
        raise ValueError(
            "Found missing serializer(s) {} needed to deserialize model that is "
            "missing from the registry of available serializers {}. Improper "
            "registration of custom serializers is suspected.".format(
                missing_serializers, REGISTRY.available_serializers
            )
        )


def _check_and_warn_for_missing_installed_packages(metadata: metadata_type) -> None:
    """Check and warn for whether installed packages are in metadata"""
    installed_packages = metadata.get(METADATA_KEY_INSTALLED_PACKAGES)
    if installed_packages is None:
        logger.warning(
            "Metadata key {} not found in metadata. This is optional for now but "
            "will soon be required. Consider re-serializing your model with a later"
            "version of the serialization package"
            "".format(METADATA_KEY_INSTALLED_PACKAGES)
        )
    elif len(installed_packages) == 0:  # it's a list, we know that from validation
        logger.warning(
            "Found empty list for metadata field {}. Consider installing `pip` so that "
            "this information can be saved.".format(METADATA_KEY_INSTALLED_PACKAGES)
        )
    else:
        pass


def _set_non_serializable_attributes_to_none(model_object: SerializableModel) -> None:
    """Set non-serializable attributes back to None"""
    for attr_name, attr_serialization_scheme in model_object.custom_serialization.items():
        if attr_serialization_scheme == ATTRIBUTE_DO_NOT_SERIALIZE:
            attr_value = getattr(model_object, attr_name)
            if not isinstance(attr_value, CustomSerializedValue):
                raise AssertionError(
                    "This should never happen. Attempting to overwrite the "
                    "attribute `{}` but it is of type {}, (value {}) and not of "
                    "type `CustomSerializedValue`. Likely, attributes have been "
                    "changed behind your back.".format(attr_name, type(attr_value), attr_value)
                )
            setattr(model_object, attr_name, None)


@validate(tar_file=TarFile, model_directory=filename_safe_string, metadata=metadata_format)
def _parse_metadata_into_model(
    tar_file: TarFile, model_directory: str, metadata: metadata_type
) -> SerializableModel:
    """Return the stored model configuration from the stored metadata."""
    needed_serializers = {
        stream_data["serializer"]
        for stream_data in metadata["attributes"].values()
        if (stream_data["serializer"], stream_data["filename"]) != ATTRIBUTE_DO_NOT_SERIALIZE
    }
    _check_and_raise_for_missing_or_null_serializer(needed_serializers)
    _check_and_warn_for_missing_installed_packages(metadata)

    attributes = {
        attr_name: _load_item_from_tarfile_and_stream_data(tar_file, model_directory, stream_data)
        for attr_name, stream_data in metadata["attributes"].items()
    }
    model_object = _load_item_from_tarfile_and_stream_data(
        tar_file, model_directory, metadata[METADATA_KEY_MODEL]
    )

    _set_non_serializable_attributes_to_none(model_object)

    if not isinstance(model_object, SerializableModel):
        raise AssertionError(
            "This should never happen. Found model of type {}. "
            "Deserialized a model that is not of type `SerializableModel`"
            "".format(type(model_object))
        )

    for attr_name, attr_value in attributes.items():
        if not isinstance(getattr(model_object, attr_name), CustomSerializedValue):
            raise AssertionError(
                "This should never happen. Attempting to overwrite the "
                "attribute `{}` but it is of type {}, (value {}) and not of type "
                "`CustomSerializedValue`. Likely, attributes have been "
                "changed behind your back.".format(attr_name, type(attr_value), attr_value)
            )
        setattr(model_object, attr_name, attr_value)

    model_object.post_deserialization_hook()  # sure to exist now

    return model_object


@validate(
    tar_file=TarFile,
    model_directory=filename_safe_string,
    attribute_name_to_stream_data=attribute_descriptor,
    model_stream_data=All(),
    gpg_home_dir=NON_EMPTY_STRING,  # has folder structure in it so not filename_safe_string
    signing_key_fingerprint=NON_EMPTY_STRING,
    passphrase=NON_EMPTY_STRING,
)
def _write_metadata_into_tarball(
    tar_file: TarFile,
    model_directory: str,
    attribute_name_to_stream_data: Dict[str, stream_type],
    model_stream_data: Any,
    gpg_home_dir: str,
    signing_key_fingerprint: str,
    passphrase: str,
) -> None:
    """Write the metadata file entry into the model tarball."""
    metadata_path = os.path.join(model_directory, METADATA_FILENAME)
    metadata = {
        "version": METADATA_FORMAT_VERSION,
        "model": model_stream_data,
        "attributes": attribute_name_to_stream_data,
        "written_on_date": datetime.utcnow().isoformat(),
        "serializing_package_version": package_version,
        "installed_packages": get_installed_packages(),
    }
    try:
        metadata_format(metadata)
    except Invalid as e:
        raise SerializationError(
            "Attempting to serialize metadata into the wrong format. {}".format(e.args)
        )

    meta_string_with_newline = json.dumps(metadata) + "\n"
    signed_meta = sign_message(
        gpg_home_dir, signing_key_fingerprint, meta_string_with_newline.encode("utf-8"), passphrase
    )
    stream = BytesIO(signed_meta)
    consume_stream_into_tarball(tar_file, metadata_path, stream)


def _write_model_into_tarball_and_get_stream_data(
    tar_file: TarFile, model_directory: str, naked_model: SerializableModel
) -> stream_type:
    """Write the actual model class into a tarball"""
    _ensure_model_is_naked(naked_model)
    model_serializer = REGISTRY.get_serializer_by_name(MODEL_SELF_SERIALIZER)
    stream, nonce, hmac_code = model_serializer.to_verifiable_stream(naked_model)
    model_path = os.path.join(model_directory, MODEL_FILE_NAME)
    consume_stream_into_tarball(tar_file, model_path, stream)
    model_stream_data = {
        "nonce": nonce,
        "filename": MODEL_FILE_NAME,
        "serializer": MODEL_SELF_SERIALIZER,
        "hmac_code": hmac_code,
    }
    return model_stream_data


def _ensure_model_is_naked(model: SerializableModel) -> None:
    """Ensure that all the attributes in a model have been nulled out"""
    for attr_name in model.custom_serialization:
        if not isinstance(getattr(model, attr_name), CustomSerializedValue):
            raise AssertionError(
                "Model has unserialized attribute {}, value: {}".format(
                    attr_name, getattr(model, attr_name)
                )
            )


def _serialize_attributes_to_tarfile(tar_file, model, model_directory) -> Dict[str, stream_type]:
    """Write the serializable attributes of a model to a tarfile"""
    serialization_scheme = model.custom_serialization
    attribute_name_to_stream_data = {}
    for attr_name, attr_serializer in serialization_scheme.items():
        if attr_serializer == ATTRIBUTE_DO_NOT_SERIALIZE:
            setattr(model, attr_name, CustomSerializedValue())
            continue
        serializer_name, filename = attr_serializer
        if MODEL_FILE_NAME == filename:
            raise ValueError(
                "Found attribute {} with filename {}. This conflicts with the "
                "model filename. The model can therefore not be "
                "serialized.".format(attr_name, filename)
            )
        # we have already checked that the serializer exists
        serializer = REGISTRY.get_serializer_by_name(serializer_name)
        attribute = getattr(model, attr_name)
        if isinstance(attribute, CustomSerializedValue):
            raise AssertionError(
                "This should not happen. Attribute `{}` is already of type "
                "CustomSerializedValue. The model has likely already been "
                "serialized, and repeating this will not work.".format(attr_name)
            )
        stream, nonce, hmac_code = serializer.to_verifiable_stream(getattr(model, attr_name))
        setattr(model, attr_name, CustomSerializedValue())

        attribute_name_to_stream_data[attr_name] = {
            "nonce": nonce,
            "filename": filename,
            "hmac_code": hmac_code,
            "serializer": serializer_name,
        }
        file_member_path = os.path.join(model_directory, filename)
        consume_stream_into_tarball(tar_file, file_member_path, stream)
    return attribute_name_to_stream_data


# ##########
# Public API
# ##########


METADATA_FORMAT_VERSION = 3


@validate(tar_file=TarFile, gpg_home_dir=voluptuous.Any(None, str))
def load_from_tarfile(
    tar_file: TarFile, gpg_home_dir: Optional[str] = None, **kwargs
) -> SerializableModel:
    """Load a model configuration from a TarFile object.

    Args:
        tar_file: TarFile, the tarball containing the model's data
        gpg_home_dir: home directory for gpg to verify models
                  ***This argument is not optional!*** It is accepted as a kwarg to maintain
                  function signature consistency across different metadata format deserializers.
        **kwargs: unused, accepted for function signature consistency across metadata formats

    Returns:
        a deserialized model. something that inherits from SerializableModel

    Raises:
        SerializationError, if the tar_file is not a valid model file.
        IntegrityError, if the serialized model fails integrity checks.
    """
    model_directory = get_model_directory_name(tar_file)

    metadata_path = os.path.join(model_directory, METADATA_FILENAME)
    with open_readonly_tarball_file(tar_file, metadata_path) as f:
        verified_metadata_bytes = verify_and_extract_message(gpg_home_dir, f.read())

    logger.info("Metadata verified correctly. Json loading metadata")
    metadata = json.loads(verified_metadata_bytes.decode("utf-8"))

    logger.info("Metadata json loaded correctly... Parsing metadata into model")
    return _parse_metadata_into_model(tar_file, model_directory, metadata)


@validate(
    tar_file=TarFile,
    model=SerializableModel,
    model_directory=filename_safe_string,
    gpg_home_dir=voluptuous.Any(None, NON_EMPTY_STRING),
    signing_key_fingerprint=voluptuous.Any(None, NON_EMPTY_STRING),
    passphrase=voluptuous.Any(None, NON_EMPTY_STRING),
)
def save_to_tarfile(
    tar_file: TarFile,
    model: SerializableModel,
    model_directory: str,
    gpg_home_dir: Optional[str] = None,
    signing_key_fingerprint: Optional[str] = None,
    passphrase: Optional[str] = None,
    **kwargs
) -> None:
    """Save a model to a TarFile object.

    Args:
        tar_file: TarFile, the tarball where the model should be saved
        model: ModelInterface object describing the model to be saved
        model_directory: string, the directory within the tarball where the model's data should go
        gpg_home_dir: home directory for gpg, for signing models
        signing_key_fingerprint: for gpg
        passphrase: to unlock key to sign model
        **kwargs: unused, accepted for function signature consistency across metadata formats
    """
    serialization_scheme = model.custom_serialization
    if METADATA_KEY_MODEL in serialization_scheme:
        raise ValueError(
            "The key {} found in model serialization scheme but is also the metadata "
            "key used to stored the bare model. While this is would in principle "
            "work, it is a terrible idea and you probably did not mean to "
            "do so.".format(METADATA_KEY_MODEL)
        )

    # loop through serializers first before trying to write anything to make
    # sure we have all of the needed ones
    needed_serializers = {
        serializer_name
        for (serializer_name, filename) in serialization_scheme.values()
        if (serializer_name, filename) != ATTRIBUTE_DO_NOT_SERIALIZE
    }
    _check_and_raise_for_missing_or_null_serializer(needed_serializers)

    logger.info("Serializing model attributes to streams")

    # first write the serializable attributes to tarfile
    attribute_name_to_stream_data = _serialize_attributes_to_tarfile(
        tar_file, model, model_directory
    )

    logger.info("Serializing model object into stream")

    # then write the model into the tarfile
    model_stream_data = _write_model_into_tarball_and_get_stream_data(
        tar_file, model_directory, model
    )

    logger.info("Writing metadata into tarball")

    # Lastly, create the model serialization metadata and include it in the tarball.
    _write_metadata_into_tarball(
        tar_file,
        model_directory,
        attribute_name_to_stream_data,
        model_stream_data,
        gpg_home_dir,
        signing_key_fingerprint,
        passphrase,
    )
