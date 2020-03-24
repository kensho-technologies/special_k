# Copyright 2020-present Kensho Technologies, LLC.
import codecs
import logging
import os
import re

from setuptools import find_packages, setup


# Python documentation recommends a single source of truth for the package version.
#  https://packaging.python.org/guides/single-sourcing-package-version/
#  #single-sourcing-the-version

PACKAGE_NAME = "special_k"


logger = logging.getLogger(__name__)


def read_file(filename):
    """Read package file as text to get name and version"""
    # intentionally *not* adding an encoding option to open. See here:
    # https://github.com/pypa/virtualenv/issues/201#issuecomment-3145690
    here = os.path.abspath(os.path.dirname(__file__))
    with codecs.open(os.path.join(here, PACKAGE_NAME, filename), "r") as f:
        return f.read()


def find_version():
    """Only define version in one place"""
    version_file = read_file("__init__.py")
    version_match = re.search(r'^__version__ = ["\']([^"\']*)["\']', version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


def find_name():
    """Only define name in one place"""
    name_file = read_file("__init__.py")
    name_match = re.search(r'^__name__ = ["\']([^"\']*)["\']', name_file, re.M)
    if name_match:
        return name_match.group(1)
    raise RuntimeError("Unable to find name string.")


REQUIRED_PACKAGES = [
    "click>=6.3,<7",
    "dill<0.4,>=0.2",
    "funcy>=1.10,<2",
    "gpg==1.10.0",
    "h5py>=2.7.1,<3",
    "joblib>=0.11,<1",
    "msgpack>=0.5.6,<1",
    "numpy>=1.10.0,<2",
    "pandas>=0.25.3,<1",
    "voluptuous>=0.11.5,<1",
]
DEV_DEPENDENCIES = [
    "black=19.10b0",
    "flake8>=3.7,<4",
    "isort>=4.3,<5",
    "pytest>=5.3.4,<6",
    "tensorflow>=1.2,<2",
]
EXTRAS_REQUIRE = {"torch": ["torch>=1.4,<=2.0"]}
EXTRAS_REQUIRE["dev"] = [
    dependency
    for extra_dependencies in EXTRAS_REQUIRE.values()
    for dependency in extra_dependencies
]
EXTRAS_REQUIRE["dev"].extend(DEV_DEPENDENCIES)

setup(
    name=find_name(),
    version=find_version(),
    packages=find_packages(),
    install_requires=REQUIRED_PACKAGES,
    extras_require=EXTRAS_REQUIRE,
    package_data={
        "": [  # please try to keep this sorted
            "pytest.ini",
            "tests/fake_keys/keyname-to-fingerprint.json",
            "tests/fake_keys/my.txt.asc",
            "tests/fake_keys/testing.pub.asc",
            "tests/fake_keys/testing.secret.asc",
            "tests/fake_keys/trustdb.txt",
        ]
    },
    python_requires=">=3",
)
