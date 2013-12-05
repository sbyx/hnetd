cmake_minimum_required(VERSION 2.8)
project(hnetd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wextra)

# TODO: split platform logic
set(HCP src/hcp.c src/hcp_notify.c src/hcp_io.c src/hcp_pa.c src/hcp_proto.c src/hcp_timeout.c)
add_executable(hnetd ${HCP} src/hnetd.c src/iface.c src/ipc.c src/platform-openwrt.c src/tlv.c src/prefix_utils.c src/pa.c)
target_link_libraries(hnetd ubox ubus blobmsg_json)

# Unit test stuff

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")

# With this, 'make check' works even in a clean tree (sigh, cmake..)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
enable_testing()
include_directories(src)

add_executable(test_dummy test/test_dummy.c)
add_test(dummy test_dummy)
add_dependencies(check test_dummy)

add_executable(test_tlv src/tlv.c test/test_tlv.c)
target_link_libraries(test_tlv ubox ubus blobmsg_json)
add_test(tlv test_tlv)
add_dependencies(check test_tlv)

add_executable(test_hcp ${HCP} src/pa.c src/prefix_utils.c src/tlv.c test/test_hcp.c)
target_link_libraries(test_hcp ubox ubus blobmsg_json)
add_test(hcp test_hcp)
add_dependencies(check test_hcp)

add_executable(test_hcp_net src/tlv.c test/test_hcp_net.c)
target_link_libraries(test_hcp_net ubox ubus blobmsg_json)
add_test(hcp_net test_hcp_net)
add_dependencies(check test_hcp_net)

add_executable(test_hcp_nio src/tlv.c test/test_hcp_nio.c)
target_link_libraries(test_hcp_nio ubox ubus blobmsg_json)
add_test(hcp_nio test_hcp_nio)
add_dependencies(check test_hcp_nio)

add_executable(test_prefix_utils src/prefix_utils.c test/test_prefix_utils.c)
add_test(prefix_utils test_prefix_utils)
add_dependencies(check test_prefix_utils)

add_executable(test_pa test/test_pa.c)
target_link_libraries(test_pa ubox)
add_test(pa test_pa)
add_dependencies(check test_pa)

add_executable(test_iface test/test_iface.c)
target_link_libraries(test_iface ubox)
add_test(iface test_iface)
add_dependencies(check test_iface)

add_executable(test_pa_store test/test_pa_store.c src/prefix_utils.c)
target_link_libraries(test_pa_store ubox)
add_test(pa_store test_pa_store)
add_dependencies(check test_pa_store)

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
