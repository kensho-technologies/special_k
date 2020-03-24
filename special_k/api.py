# Copyright 2020-present Kensho Technologies, LLC.
from io import BytesIO
import logging
import tarfile

from . import model_metadata
from .exceptions import ModelValidationError
from .serializable_model import SerializableModel
from .signing import add_trusted_keys_to_gpg_home_dir
from .utils import get_temporary_directory


logger = logging.getLogger(__name__)


def _run_model_validation_wrapper(
    serializable_model: SerializableModel, run_model_validation: bool
) -> None:
    """Run model validation or warn the user that the model may break upon use"""
    if run_model_validation:
        # run checks to ensure that the model is safe to save or load
        try:
            serializable_model.validate_model()
        except ModelValidationError as e:
            logger.error(
                "Model validation failed. This could be because the current "
                "environment differs irreconcilably from that which built and "
                "trained the model or because the model was built incorrectly in the "
                "first place.\n%s",
                e.args,
                exc_info=True,
            )
            raise
    else:
        # scare tactics
        logger.warning(
            "Saving or loading model without running validation. This model may break "
            "when you try to use it! Proceed with caution, and do not do this in "
            "production."
        )


def _load_model_from_tarball_stream(tarball_stream, gpg_home_dir):
    """Load a model from a tarball stream

    Args:
        tarball_stream: a readable stream
        gpg_home_dir: home directory for gpg to verify signed model (e.g. path/to/.gnupg)

    Returns:
        a SerializableModel
    """
    tarball_stream.seek(0)
    with tarfile.open(mode="r", fileobj=tarball_stream) as tar_file:
        return model_metadata.load_from_tarfile(tar_file, gpg_home_dir=gpg_home_dir)


def load_model_from_tarball_stream(
    tarball_stream, gpg_home_dir=None, run_model_validation=True
) -> SerializableModel:
    """Load a model from a tarball stream

    Args:
        tarball_stream: a readable stream
        gpg_home_dir: home directory for gpg to verify signed model (e.g. path/to/.gnupg)
            default None will make a temp dir and add the trusted keys to it
        run_model_validation: bool, whether to run validate_model() after deserialization.
            Default true; all models should be validated after loading, and the user should have
            a very good reason if they choose not to run this check.

    Returns:
        A SerializableModel that was serialized to `tarball_stream`. It is cryptographically checked
            to ensure that NOTHING has changed, and it has been validated to make sure that it
            performs as it did before serialization
    """
    if gpg_home_dir is None:
        with get_temporary_directory() as tmp_dir:
            add_trusted_keys_to_gpg_home_dir(tmp_dir)
            deserialized_model = _load_model_from_tarball_stream(tarball_stream, tmp_dir)
    else:
        deserialized_model = _load_model_from_tarball_stream(tarball_stream, gpg_home_dir)

    _run_model_validation_wrapper(deserialized_model, run_model_validation)
    return deserialized_model


def _load_model_from_tarball(tarball_path, gpg_home_dir):
    """Load a model from a tarball

    Args:
        tarball_path: a path to a model gzipped tar file
        gpg_home_dir: home directory for gpg to verify signed model (e.g. path/to/.gnupg)

    Returns:
        something of type SerializableModel
    """
    with tarfile.open(tarball_path, "r") as tar_file:
        return model_metadata.load_from_tarfile(tar_file, gpg_home_dir=gpg_home_dir)


def load_model_from_tarball(
    tarball_path, gpg_home_dir=None, run_model_validation=True
) -> SerializableModel:
    """Load a model from a tarball

    Args:
        tarball_path: a path to a model gzipped tar file
        gpg_home_dir: home directory for gpg to verify signed model (e.g. path/to/.gnupg)
            default None will make a temp dir and add the trusted keys to it
        run_model_validation: bool, whether to run validate_model() after deserialization.
            Default true; all models should be validated after loading, and the user should have
            a very good reason if they choose not to run this check.

    Returns:
        A SerializableModel that was serialized to `tarball_path`. It is cryptographically checked
            to ensure that NOTHING has changed, and it has been validated to make sure that it
            performs as it did before serialization
    """
    if gpg_home_dir is None:
        with get_temporary_directory() as tmp_dir:
            add_trusted_keys_to_gpg_home_dir(tmp_dir)
            deserialized_model = _load_model_from_tarball(tarball_path, tmp_dir)
    else:
        deserialized_model = _load_model_from_tarball(tarball_path, gpg_home_dir)

    _run_model_validation_wrapper(deserialized_model, run_model_validation)
    return deserialized_model


def save_model_to_tarball_stream(
    model: SerializableModel,
    gpg_home_dir,
    signing_key_fingerprint,
    passphrase,
    run_model_validation=True,
):
    """Save a model to a tarball stream.

    WARNING: THIS DESTROYS THE MODEL AND YOU WILL NOT BE ABLE TO USE IT AFTERWARDS.

    Args:
        model: of type Serializable model
        gpg_home_dir: home directory for gpg to sign the model (e.g. path/to/.gnupg)
        signing_key_fingerprint: key in the db in gpg_home_dir to use to sign the model
        passphrase: passphrase for the key to use for signing
        run_model_validation: bool, whether to run validate_model() before serialization.
            Default true; all models should be validated before saving, and the user should have
            a very good reason if they choose not to run this check.

    Returns:
        a stream with the tarball (not rewound to the beginning)
    """
    _run_model_validation_wrapper(model, run_model_validation)

    stream = BytesIO()
    with tarfile.open(mode="w:gz", fileobj=stream) as tar_file:
        model_metadata.save_to_tarfile(
            tar_file,
            model,
            gpg_home_dir=gpg_home_dir,
            signing_key_fingerprint=signing_key_fingerprint,
            passphrase=passphrase,
        )
        return stream


def save_model_to_tarball(
    model,
    tarball_path,
    gpg_home_dir,
    signing_key_fingerprint,
    passphrase,
    run_model_validation=True,
):
    """Save a model to a tarball

    WARNING: THIS DESTROYS THE MODEL AND YOU WILL NOT BE ABLE TO USE IT AFTERWARDS.

    Args:
        model: of type Serializable model
        tarball_path: path to which to save the gzipped tarball
        gpg_home_dir: home directory for gpg to sign the model (e.g. path/to/.gnupg)
        signing_key_fingerprint: key in the db in gpg_home_dir to use to sign the model
        passphrase: passphrase for the key to use for signing
        run_model_validation: bool, whether to run validate_model() before serialization.
            Default true; all models should be validated before saving, and the user should have
            a very good reason if they choose not to run this check.
    """
    _run_model_validation_wrapper(model, run_model_validation)
    with tarfile.open(tarball_path, mode="w:gz") as tar_file:
        model_metadata.save_to_tarfile(
            tar_file,
            model,
            gpg_home_dir=gpg_home_dir,
            signing_key_fingerprint=signing_key_fingerprint,
            passphrase=passphrase,
        )
