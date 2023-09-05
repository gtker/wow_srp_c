#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INCLUDE_DIR=${SCRIPT_DIR}/include/wow_srp

cbindgen --cpp-compat --lang c --crate wow_srp_c --output "${INCLUDE_DIR}/wow_srp.h" \
    && cbindgen --cpp-compat --lang c++ --crate wow_srp_c --output "${INCLUDE_DIR}/wow_srp.hpp" 

