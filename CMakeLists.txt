cmake_minimum_required(VERSION 2.8.8)
# object library support was added in 2.8.8

project(hnetd C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wno-gnu -Wextra)

if(${L_LEVEL})
  add_definitions(-DL_LEVEL=${L_LEVEL})
endif(${L_LEVEL})

if(${VERSION})
  add_definitions(-DHNETD_VERSION=${VERSION})
else(${VERSION})
  execute_process(COMMAND git describe --always OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
  add_definitions(-DHNETD_VERSION=${VERSION})
endif(${VERSION})

OPTION(COVERAGE "build with coverage" OFF)

if(${APPLE})
  # Xcode 4.* target breaks because it doesn't add 'system-ish' include paths
  include_directories(/usr/local/include /opt/local/include)
  link_directories(/usr/local/lib /opt/local/lib)
endif(${APPLE})

if (${COVERAGE})
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
endif (${COVERAGE})

if (${EXTRA_INCLUDE_DIR})
  include_directories(${EXTRA_INCLUDE_DIR})
endif (${EXTRA_INCLUDE_DIR})

if (${EXTRA_LINK_DIR})
  link_directories(${EXTRA_LINK_DIR})
endif (${EXTRA_LINK_DIR})

if(${BACKEND} MATCHES "openwrt")
  set(BACKEND_SOURCE "src/platform-openwrt.c")
  set(BACKEND_LINK "ubus")
else(${BACKEND} MATCHES "openwrt")
  set(BACKEND_SOURCE src/platform-generic.c src/ipc.c)
  set(BACKEND_LINK "")
  add_definitions(-DWITH_IPC=1)
  install(PROGRAMS generic/dhcp.script generic/dhcpv6.script generic/ohp.script generic/pcp.script generic/utils.script DESTINATION share/hnetd/)
  install(PROGRAMS generic/hnetd-backend DESTINATION sbin/)
  # Symlinks for different hnetd aliases
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifup)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifdown)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-dump)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-call)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifresolve)")
endif(${BACKEND} MATCHES "openwrt")

# hnetd and it's various pieces
add_library(L_PU OBJECT src/prefix_utils.c)
set(PU $<TARGET_OBJECTS:L_PU>)
add_library(L_BT OBJECT src/btrie.c)
set(BT $<TARGET_OBJECTS:L_BT>)
add_library(L_TLV OBJECT src/tlv.c)
set(TLV $<TARGET_OBJECTS:L_TLV>)
add_library(L_PA_DATA OBJECT src/pa_data.c)
set(PA_D ${BT} $<TARGET_OBJECTS:L_PA_DATA>)
add_library(L_PA_STORE OBJECT src/pa_store.c)
set(PA_S $<TARGET_OBJECTS:L_PA_STORE>)
add_library(L_PA_TIMER OBJECT src/pa_timer.c)
set(PA_T $<TARGET_OBJECTS:L_PA_TIMER>)
add_library(L_PA_PD OBJECT src/pa_pd.c)
set(PA_SP ${PA_S} $<TARGET_OBJECTS:L_PA_PD>)
add_library(L_PA OBJECT src/pa.c src/pa_local.c src/pa_core.c)
set(PA ${PA_SP} ${PA_D} ${PA_T} $<TARGET_OBJECTS:L_PA>)
add_library(L_HNCP_BASE OBJECT src/hncp.c src/hncp_notify.c src/hncp_timeout.c)
set(HNCP_BASE $<TARGET_OBJECTS:L_HNCP_BASE> ${PU} ${TLV})
add_library(L_HNCP_PROTO OBJECT src/hncp_proto.c)
set(HNCP_WITH_PROTO ${HNCP_BASE} $<TARGET_OBJECTS:L_HNCP_PROTO>)
add_library(L_HNCP_GLUE OBJECT src/hncp_pa.c src/hncp_sd.c)
set(HNCP_WITH_GLUE ${HNCP_WITH_PROTO} $<TARGET_OBJECTS:L_HNCP_GLUE>)
add_library(L_HNCP_IO OBJECT src/hncp_io.c)
set(HNCP_IO $<TARGET_OBJECTS:L_HNCP_IO>)
set(HNCP ${HNCP_WITH_GLUE} ${HNCP_IO})
add_executable(hnetd ${HNCP} src/hncp_routing.c src/hncp_dump.c src/hnetd.c src/iface.c src/pd.c ${PA} src/ ${BACKEND_SOURCE})
target_link_libraries(hnetd ubox blobmsg_json resolv ${BACKEND_LINK})
install(TARGETS hnetd DESTINATION sbin/)

# Unit test stuff

# With this, 'make check' works even in a clean tree (sigh, cmake..)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
enable_testing()
include_directories(src)

add_executable(test_dummy test/test_dummy.c)
add_test(dummy test_dummy)
add_dependencies(check test_dummy)

add_executable(test_tlv test/test_tlv.c ${TLV})
target_link_libraries(test_tlv ubox ${BACKEND_LINK} blobmsg_json)
add_test(tlv test_tlv)
add_dependencies(check test_tlv)

add_executable(test_hncp test/test_hncp.c ${HNCP} ${PA})
target_link_libraries(test_hncp ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp test_hncp)
add_dependencies(check test_hncp)

add_executable(test_hncp_net test/test_hncp_net.c ${HNCP_WITH_GLUE} ${BT})
target_link_libraries(test_hncp_net ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_net test_hncp_net)
add_dependencies(check test_hncp_net)

add_executable(test_hncp_sd test/test_hncp_sd.c ${HNCP_WITH_PROTO} ${BT})
target_link_libraries(test_hncp_sd ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_sd test_hncp_sd)
add_dependencies(check test_hncp_sd)

add_executable(test_hncp_nio test/test_hncp_nio.c ${PU} ${TLV})
target_link_libraries(test_hncp_nio ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_nio test_hncp_nio)
add_dependencies(check test_hncp_nio)

add_executable(test_hncp_bfs test/test_hncp_bfs.c ${HNCP_BASE} ${HNCP_IO} ${BT})
target_link_libraries(test_hncp_bfs ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_bfs test_hncp_bfs)
add_dependencies(check test_hncp_bfs)

add_executable(test_prefix_utils test/test_prefix_utils.c ${PU})
target_link_libraries(test_prefix_utils ubox)
add_test(prefix_utils test_prefix_utils)
add_dependencies(check test_prefix_utils)

add_executable(test_pa test/test_pa.c ${PA_SP} ${BT})
target_link_libraries(test_pa ubox)
add_test(pa test_pa)
add_dependencies(check test_pa)

add_executable(test_pa_pd test/test_pa_pd.c ${BT})
target_link_libraries(test_pa_pd ubox)
add_test(pa_pd test_pa_pd)
add_dependencies(check test_pa_pd)

add_executable(test_iface test/test_iface.c ${BT})
target_link_libraries(test_iface ubox)
add_test(iface test_iface)
add_dependencies(check test_iface)

add_executable(test_pa_store test/test_pa_store.c ${PA_S} ${PA_D} ${PU} ${PA_T})
target_link_libraries(test_pa_store ubox)
add_test(pa_store test_pa_store)
add_dependencies(check test_pa_store)

add_executable(test_pa_data test/test_pa_data.c ${PA_D} ${PU})
target_link_libraries(test_pa_data ubox)
add_test(pa_data test_pa_data)
add_dependencies(check test_pa_data)

add_executable(test_btrie test/test_btrie.c ${PU})
target_link_libraries(test_btrie ubox)
add_test(btrie test_btrie)
add_dependencies(check test_btrie)

# Packaging rules
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "hnetd")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
