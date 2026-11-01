"""Entry point: `python -m beacon`. Commands are added as the modules land (run, keygen, status)."""

import argparse

from beacon import __version__


def main() -> None:
    parser = argparse.ArgumentParser(prog="beacon", description="Huddle beacon")
    parser.add_argument("--version", action="version", version=f"huddle-beacon {__version__}")
    parser.parse_args()
    parser.print_help()


if __name__ == "__main__":
    main()
