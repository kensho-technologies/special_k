# Installation
`special_k` requires the following packages to function properly:
- `gpg`: the "gpg" command line tool, required to serialize and deserialize models
- `gpgme`: the headers and binary interface for running GPG operations programmatically
- `swig`: a tool that automatically generates Python bindings based on C/C++ headers

These packages can be installed on OSX with `brew install gnupg2 gpgme swig`
and on Debian-based Linux with `apt-get install gnupg2 libgpgme-dev swig`.

`special_k` can be installed with `pip install special_k`.
This package is supported only with Python 3, and the recommended Docker image for usage with this package is `python:3.6-stretch`.

# GPG Setup
`special_k` ensures safe serialization and deserialization of models by using GPG keys to sign model metadata.
Explanations of how GPG works and the PGP trust model are outside the scope of this documentation;
please see the [official GPG documentation](https://gnupg.org/documentation/index.html) for more information.

## Key Generation
Each GPG key can be generated with `gpg2 --export --armor --output=key1.pub.asc $EMAIL_OF_KEY_TO_EXPORT`,
and fingerprints of these keys can be listed using `gpg2 --list-keys --with-fingerprint`.
Note: you may need to specify a `--homedir` if your default `~/.gnupg` is not correct.

## Configuration
The following steps allow trusted keys to be automatically imported if your GPG home dir is not set
(e.g. if keys are imported from version control or a configuration file).
They can safely be skipped if your keys are present in your GPG home dir.

First, construct a directory to contain GPG keys.
A public-private GPG keypair is used to sign model metadata after serialization
and to verify the signature on the model metadata before deserialization.
Therefore, your GPG key directory should contain any private keys you are using to sign serialized models,
and public keys of any trusted sources of models you would like to deserialize.
N.B.: Do *not* check private keys into your git repository.

Your GPG key directory should contain the following files:
- The keys themselves, e.g. `key1.pub.asc`, `key2.pub.asc`, ...
- `trustdb.txt`: a file assigning levels of trust to each public key in this directory.
You likely have a single root of trust, in which case you would have a single line in `trustdb.txt` to ultimately trust that key,
i.e. `FINGERPRINT_OF_ULTIMATELY_TRUSTED_KEY:6:`.
- `keyname-to-fingerprint.json`: a file mapping the names of the public keys to their fingerprints, e.g. `{ "key1.pub.asc": "FINGERPRINT_OF_KEY1" }`
- `__init__.py`: an empty file

To use this trusted keys directory with `special_k`,
simply set the environment variable `SERIALIZATION_TRUSTED_KEYS_DIR` to the location of this directory,
or include the following lines in `__init__.py` to set the environment variable when this module is imported:
```python
import os

os.environ["SERIALIZATION_TRUSTED_KEYS_DIR"] = os.path.dirname(os.path.abspath(__file__))
```

# Next Steps
After installing the library and setting up GPG keys, it's time to
[create your first ML model compatible with the special_k API](./usage.md#creating-a-serializable-model).
