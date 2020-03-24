# Copyright 2020-present Kensho Technologies, LLC.
from io import BytesIO
from os import path
from tarfile import TarFile
from types import ModuleType
from typing import Tuple

from . import metadata_format_v3
from ..exceptions import SerializationError
from ..serializable_model import SerializableModel
from ..utils import (
    consume_stream_into_tarball,
    get_model_directory_name,
    make_model_directory,
    open_readonly_tarball_file,
)


META_VERSION_FILENAME = "meta.version"
RECOGNIZED_METADATA_VERSIONS = {
    metadata_format_v3.METADATA_FORMAT_VERSION: metadata_format_v3,
    # More versions can be added here
}


def get_current_metadata_format() -> Tuple[int, ModuleType]:
    """Return the version number and module that has the preferred way to serialize new models."""
    max_version = max(RECOGNIZED_METADATA_VERSIONS.keys())
    return max_version, RECOGNIZED_METADATA_VERSIONS[max_version]


def load_from_tarfile(tar_file: TarFile, **kwargs) -> SerializableModel:
    """Load a model configuration from a TarFile object.

    Args:
        tar_file: TarFile, the tarball containing the model's data
        **kwargs: arbitrary additional data that may be required to correctly deserialize the model,
                  such as cryptographic keys or other configuration.

    Returns:
        version-dependent value:  (Add more here if more versions are supported)
        - in V3: the deserialized model directly!

    Raises:
        SerializationError, if the tar_file is not a valid model file.
        IntegrityError, if the serialized model fails integrity checks.
    """
    model_directory = get_model_directory_name(tar_file)
    meta_version_path = path.join(model_directory, META_VERSION_FILENAME)

    # Read the metadata format version.
    with open_readonly_tarball_file(tar_file, meta_version_path) as f:
        version = int(f.read())

    metadata_format = RECOGNIZED_METADATA_VERSIONS.get(version, None)
    if metadata_format is None:
        raise SerializationError(
            "Unrecognized model serialization version! Version was {}, "
            "but this package only supports versions: {}".format(
                version, list(RECOGNIZED_METADATA_VERSIONS.keys())
            )
        )

    return metadata_format.load_from_tarfile(tar_file, **kwargs)


def save_to_tarfile(tar_file: TarFile, model: SerializableModel, **kwargs) -> None:
    """Save a model to a TarFile object.

    Args:
        tar_file: TarFile, the tarball to which the model should be saved
        model: ModelInterface object describing the model to be saved
        **kwargs: arbitrary additional data that may be required to correctly serialize the model,
                  such as cryptographic keys or other configuration.
    """
    model_directory = make_model_directory(tar_file)

    version_number, metadata_serializer = get_current_metadata_format()

    # Write the metadata format version.
    meta_version_path = path.join(model_directory, META_VERSION_FILENAME)
    stream = BytesIO()
    version_str = str(version_number) + "\n"
    stream.write(version_str.encode("utf-8"))
    consume_stream_into_tarball(tar_file, meta_version_path, stream)

    # Write the actual model into the tarball.
    metadata_serializer.save_to_tarfile(tar_file, model, model_directory, **kwargs)
