add_library(wow_srp_cpp src/wow_srp_cpp.cpp)
target_sources(wow_srp_cpp PUBLIC
        FILE_SET HEADERS
        BASE_DIRS
        include
        FILES
        include/wow_srp_cpp/client.hpp
        include/wow_srp_cpp/server.hpp
        include/wow_srp_cpp/vanilla.hpp
        include/wow_srp_cpp/wow_srp.hpp
)
add_library(WowSrp::wow_srp_cpp ALIAS wow_srp_cpp)

target_link_libraries(wow_srp_cpp PRIVATE WowSrp::wow_srp)
set_target_properties(wow_srp_cpp PROPERTIES INSTALL_RPATH $ORIGIN)
