# Copyright 2020-present Kensho Technologies, LLC.
import logging
import sys

import click
import gpg

from ..signing import (
    DAYS_WARNING_FOR_KEY_EXPIRATION,
    add_trusted_keys_to_gpg_home_dir,
    get_days_until_expiry,
)
from ..utils import get_temporary_directory


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def check_gpg_key_expiry(
    days_warning_for_key_expiration: int = DAYS_WARNING_FOR_KEY_EXPIRATION
) -> bool:
    """Check key expirations

    Args:
        days_warning_for_key_expiration: warn if a key expires within this number of days.
            Defaults to 30.

    Returns:
        True if no keys are soon to expire or already expired, False otherwise
    """
    with get_temporary_directory() as gpg_homedir:
        add_trusted_keys_to_gpg_home_dir(gpg_homedir)
        with gpg.Context(home_dir=gpg_homedir) as ctx:
            fpr_to_expiry = get_days_until_expiry(ctx)
            no_keys_close_to_expiry = True
            for fpr, days_to_expiry in fpr_to_expiry.items():
                if days_to_expiry < 0:
                    no_keys_close_to_expiry = False
                    action_message = "KEY IS EXPIRED!"
                elif days_to_expiry < days_warning_for_key_expiration:
                    no_keys_close_to_expiry = False
                    action_message = "UPDATE KEY ASAP!!!!"
                else:
                    action_message = "OK for now, but stay tuned"
                logger.info(
                    "Key (FPR: %s) expires in %s days. %s", fpr, days_to_expiry, action_message
                )

    return no_keys_close_to_expiry


@click.command()
@click.argument("days_before_warning", required=False)
def main(days_before_warning) -> None:
    """Log info about when GPG keys will expire"""
    no_keys_close_to_expiry = check_gpg_key_expiry(days_before_warning)
    if no_keys_close_to_expiry:
        sys.exit(0)
    sys.exit(1)
