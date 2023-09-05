#!/usr/bin/env python3
import subprocess
import typing
from os import path
from pathlib import Path
from subprocess import run as run_cmd

SCRIPT_DIR = Path(path.dirname(path.realpath(__file__)))
INCLUDE_DIR = SCRIPT_DIR / "include" / "wow_srp"

DEFINES_TO_FILES: dict[str, str] = {
    "VALUES": "values",
    "CLIENT": "client",
    "SERVER": "server",
    "WRATH": "wrath",
    "TBC": "tbc",
    "VANILLA": "vanilla"
}


def define_to_file(define: str) -> str:
    for key in DEFINES_TO_FILES:
        if key in define:
            return DEFINES_TO_FILES[key]

    raise Exception(f"invalid define '{define}'")


def split_includes(output: str) -> dict[str, list[str]]:
    C_INCLUDES = ["#pragma once", "", "#include <stdint.h>", ""]

    files = {}
    for value in DEFINES_TO_FILES.values():
        files[value] = C_INCLUDES.copy()

    current_file: typing.Optional[str] = None

    for line in output.splitlines():
        if "#include" in line:
            continue
        elif line.strip() == "":
            continue
        elif "#if defined" in line:
            current_file = define_to_file(line)
        elif "WOW_SRP_LARGE_SAFE_PRIME_LITTLE_ENDIAN" in line:
            files["values"].append(line)
        elif "extern \"C\"" in line or "__cplusplus" in line:
            for value in DEFINES_TO_FILES.values():
                files[value].append(line)
        elif "#endif" in line:
            files[current_file].append('\n')
            current_file = None

        elif current_file is not None:
            files[current_file].append(line)
        else:
            raise Exception(f"invalid line '{line}'")

    return files


def write_files(files: dict[str, list[str]]):
    for file, content in files.items():
        content = '\n'.join(content)
        filename = f"{file}.h"
        with open(INCLUDE_DIR / filename, "w") as f:
            f.write(content)


def main():
    c_output = run_cmd(["cbindgen", "--cpp-compat", "--lang", "c"], stdout=subprocess.PIPE, check=True).stdout.decode(
        'utf-8')
    write_files(split_includes(c_output))


if __name__ == "__main__":
    main()
