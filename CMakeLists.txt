cmake_minimum_required(VERSION 2.8)
project(hnetd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wextra)

# TODO: split platform logic
add_executable(hnetd src/hcp.c src/hnetd.c src/iface.c src/ipc.c src/platform-openwrt.c src/tlv.c)
target_link_libraries(hnetd ubox ubus blobmsg_json)

# Unit test stuff

# With this, 'make check' works even in a clean tree (sigh, cmake..)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
enable_testing()
include_directories(src)

add_executable(test_dummy test/test_dummy.c)
add_test(dummy test_dummy)
add_dependencies(check test_dummy)

add_executable(test_hcp src/hcp.c src/tlv.c test/test_hcp.c)
target_link_libraries(test_hcp ubox ubus blobmsg_json)
add_test(hcp test_hcp)
add_dependencies(check test_hcp)


# Installation rules
install(TARGETS hnetd DESTINATION sbin/)

# Packaging rules
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "hnetd")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
