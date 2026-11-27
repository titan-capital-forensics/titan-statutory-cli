"""TITAN Statutory Gate CLI package.

Entity: TITAN Capital Forensics LLC (Albuquerque, New Mexico, USA)
"""

from .cli import (
    CLI_VERSION,
    DEFAULT_AUTHORITY_PUBKEY_B64,
    main,
    parse_cli_args,
    run_cli,
    verify_ed25519,
)

__version__ = CLI_VERSION

__all__ = [
    "CLI_VERSION",
    "DEFAULT_AUTHORITY_PUBKEY_B64",
    "__version__",
    "main",
    "parse_cli_args",
    "run_cli",
    "verify_ed25519",
]
