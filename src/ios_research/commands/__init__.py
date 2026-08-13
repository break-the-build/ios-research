"""CLI command groups.

Each module exposes ``register(subparsers, parent)`` which attaches one or more
subcommands and sets ``func`` to a handler ``func(ctx, args) -> Result``.
"""
