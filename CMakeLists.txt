cmake_minimum_required(VERSION 2.8)
project(hnetd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wextra)

if(${L_LEVEL})
	add_definitions(-DL_LEVEL=${L_LEVEL})
endif(${L_LEVEL})


if(${BACKEND} MATCHES "openwrt")
	set(BACKEND_SOURCE "src/platform-openwrt.c")
	set(BACKEND_LINK "ubus")
else(${BACKEND} MATCHES "openwrt")
	set(BACKEND_SOURCE "src/platform-generic.c")
	set(BACKEND_LINK "")
        install(PROGRAMS generic/dhcp.script generic/dhcpv6.script DESTINATION share/hnetd/)
        install(PROGRAMS generic/hnetd-backend DESTINATION sbin/)
        # Symlinks for different hnetd aliases
        install(CODE "execute_process(COMMAND ln -s hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifup)")
        install(CODE "execute_process(COMMAND ln -s hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifdown)")
        install(CODE "execute_process(COMMAND ln -s hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-call)")
endif(${BACKEND} MATCHES "openwrt")

# TODO: split platform logic
set(HNCP_NIO_BASE src/hncp.c src/hncp_notify.c src/hncp_proto.c src/hncp_timeout.c src/prefix_utils.c src/tlv.c)
set(HNCP_NIO ${HNCP_NIO_BASE} src/hncp_pa.c src/hncp_sd.c)
set(HNCP ${HNCP_NIO} src/hncp_io.c)
add_executable(hnetd ${HNCP} src/hncp_routing.c src/hnetd.c src/iface.c src/ipc.c src/pa.c src/pa_store.c ${BACKEND_SOURCE})
target_link_libraries(hnetd ubox blobmsg_json ${BACKEND_LINK})

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

add_executable(test_hncp ${HNCP} src/pa.c src/pa_store.c src/prefix_utils.c src/tlv.c test/test_hncp.c)
target_link_libraries(test_hncp ubox ubus blobmsg_json)
add_test(hncp test_hncp)
add_dependencies(check test_hncp)

add_executable(test_hncp_net ${HNCP_NIO} test/test_hncp_net.c)
target_link_libraries(test_hncp_net ubox ubus blobmsg_json)
add_test(hncp_net test_hncp_net)
add_dependencies(check test_hncp_net)

add_executable(test_hncp_pa ${HNCP_NIO} test/test_hncp_pa.c)
target_link_libraries(test_hncp_pa ubox ubus blobmsg_json)
add_test(hncp_pa test_hncp_pa)
add_dependencies(check test_hncp_pa)

add_executable(test_hncp_sd ${HNCP_NIO_BASE} test/test_hncp_sd.c)
target_link_libraries(test_hncp_sd ubox ubus blobmsg_json)
add_test(hncp_sd test_hncp_sd)
add_dependencies(check test_hncp_sd)

add_executable(test_hncp_nio src/tlv.c test/test_hncp_nio.c src/prefix_utils.c)
target_link_libraries(test_hncp_nio ubox ubus blobmsg_json)
add_test(hncp_nio test_hncp_nio)
add_dependencies(check test_hncp_nio)

add_executable(test_hncp_bfs test/test_hncp_bfs.c src/hncp.c src/hncp_notify.c src/hncp_timeout.c src/hncp_io.c src/prefix_utils.c src/tlv.c)
target_link_libraries(test_hncp_bfs ubox ubus blobmsg_json)
add_test(hncp_bfs test_hncp_bfs)
add_dependencies(check test_hncp_bfs)

add_executable(test_prefix_utils src/prefix_utils.c test/test_prefix_utils.c)
add_test(prefix_utils test_prefix_utils)
add_dependencies(check test_prefix_utils)

add_executable(test_pa test/test_pa.c src/pa_store.c)
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
