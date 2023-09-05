cmake_minimum_required(VERSION 3.15)
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.4
)
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH Cargo.toml)

target_include_directories(wow_srp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
add_library(wow_srp::wow_srp ALIAS wow_srp)
