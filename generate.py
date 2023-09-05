#!/usr/bin/env python3
from os import path
from pathlib import Path
from subprocess import run as run_cmd

SCRIPT_DIR = Path(path.dirname(path.realpath(__file__)))
INCLUDE_DIR = SCRIPT_DIR / "include" / "wow_srp"


def main():
    run_cmd(["cbindgen", "--cpp-compat", "--lang", "c", "--output", f"{INCLUDE_DIR}/wow_srp.h"])
    run_cmd(["cbindgen", "--cpp-compat", "--lang", "c++", "--output", f"{INCLUDE_DIR}/wow_srp.hpp"])


if __name__ == "__main__":
    main()
