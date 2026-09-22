"""CLI application entry point.

Internal to ``vnc_remote_secure.cli`` — not part of the public API.
"""
import os
import sys

from vnc_remote_secure.cli._parser import create_parser


def main():
    """Run the CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Wire the global verbosity flags to the logging level — they were
    # parsed but never reached setup_logging, so --verbose/--quiet had
    # no effect on log output.
    if getattr(args, 'verbose', False) or getattr(args, 'quiet', False):
        import logging

        from vnc_remote_secure.core.logging import setup_logging
        setup_logging(verbose=getattr(args, 'verbose', False))
        if getattr(args, 'quiet', False):
            logging.getLogger('vnc_remote_secure').setLevel(
                logging.WARNING)

    if not hasattr(args, 'func'):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return 130
    except Exception as e:
        # Honour both `--verbose` and the documented `VERBOSE` env var so
        # operators can get full tracebacks without modifying the command.
        verbose = (hasattr(args, 'verbose') and args.verbose) or \
            os.environ.get('VERBOSE', 'false').lower() in ('true', '1', 'yes')
        if verbose:
            raise
        print(f"Error: {e}", file=sys.stderr)
        return 1
