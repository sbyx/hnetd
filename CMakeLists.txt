cmake_minimum_required(VERSION 2.8.8)
# object library support was added in 2.8.8

project(hnetd C)
INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(JSONC REQUIRED json-c)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wno-gnu -Wextra)

if(${L_LEVEL})
  add_definitions(-DL_LEVEL=${L_LEVEL})
endif(${L_LEVEL})

add_definitions(-DCMAKE_INSTALL_PREFIX="${CMAKE_INSTALL_PREFIX}")

if(${VERSION})
  add_definitions(-DHNETD_VERSION=${VERSION})
else(${VERSION})
  execute_process(COMMAND git describe --always OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
  add_definitions(-DHNETD_VERSION=${VERSION})
endif(${VERSION})

if(${DTLS_OPENSSL})
  set(DTLS_SOURCE src/dtls.c)
  set(TRUST_SOURCE src/dncp_trust.c)
  set(DTLS_LINK crypto ssl)
  set(DTLS 1)
  add_definitions(-DDTLS=1 -DDTLS_OPENSSL=1)
  find_package(OpenSSL REQUIRED)
else()
  set(DTLS_SOURCE "")
  set(TRUST_SOURCE "")
  set(DTLS_LINK "")
endif()

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
  set(BACKEND_SOURCE "src/platform-generic.c")
  install(PROGRAMS generic/dhcp.script generic/dhcpv6.script generic/multicast.script generic/ohp.script generic/pcp.script generic/utils.script DESTINATION share/hnetd/)
  install(PROGRAMS generic/hnetd-backend generic/hnetd-routing DESTINATION sbin/)
  # Symlinks for different hnetd aliases
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifup)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifdown)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-dump)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-call)")
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-ifresolve)")
if(${DTLS})
  install(CODE "execute_process(COMMAND ln -sf hnetd \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/sbin/hnet-trust)")
endif(${DTLS})
endif(${BACKEND} MATCHES "openwrt")

# hnetd and it's various pieces
add_library(L_HT OBJECT src/hnetd_time.c)
set(HT $<TARGET_OBJECTS:L_HT>)
add_library(L_PX OBJECT src/prefix.c)
set(PX $<TARGET_OBJECTS:L_PX>)
add_library(L_BT OBJECT src/btrie.c)
set(BT $<TARGET_OBJECTS:L_BT>)
add_library(L_BO OBJECT src/bitops.c)
set(BO $<TARGET_OBJECTS:L_BO>)
add_library(L_PU OBJECT src/prefix_utils.c)
set(PU ${BO} ${PX} $<TARGET_OBJECTS:L_PU>)
add_library(L_TLV OBJECT src/tlv.c)
set(TLV $<TARGET_OBJECTS:L_TLV>)
add_library(L_DNCP_BASE OBJECT src/dncp.c src/dncp_notify.c src/dncp_timeout.c)
set(DNCP_BASE $<TARGET_OBJECTS:L_DNCP_BASE> ${PU} ${TLV})
add_library(L_PA OBJECT src/pa_core.c src/pa_filters.c src/pa_rules.c src/pa_store.c)
set(PA ${DNCP_BASE} ${BT} $<TARGET_OBJECTS:L_PA>)
add_library(L_DNCP_PROTO OBJECT src/dncp_proto.c)
set(DNCP_WITH_PROTO ${PA} $<TARGET_OBJECTS:L_DNCP_PROTO>)
add_library(L_HNCP_GLUE OBJECT src/hncp.c src/hncp_pa.c src/hncp_sd.c src/hncp_link.c src/exeq.c src/hncp_multicast.c)
set(HNCP_WITH_GLUE ${DNCP_WITH_PROTO} $<TARGET_OBJECTS:L_HNCP_GLUE>)
add_library(L_HNCP_IO OBJECT src/hncp_io.c ${DTLS_SOURCE} src/udp46.c)
set(HNCP_IO $<TARGET_OBJECTS:L_HNCP_IO>)
set(HNCP ${HNCP_WITH_GLUE} ${HNCP_IO}  ${TRUST_SOURCE})
add_executable(hnetd ${HNCP} ${HT} src/hncp_routing.c src/hncp_dump.c src/hncp_tunnel.c src/hnetd.c src/iface.c src/pd.c src/ ${BACKEND_SOURCE})
target_link_libraries(hnetd ubox resolv blobmsg_json ${BACKEND_LINK} ${DTLS_LINK})
install(TARGETS hnetd DESTINATION sbin/)

# Fix for SSL build please :p -MSt
# Build DNCP static library
#add_library(dncp STATIC src/hnetd_time.c src/prefix.c src/tlv.c src/dncp.c src/dncp_notify.c src/dncp_timeout.c src/dncp_proto.c)

# libdncp example
#add_executable(libdncp_example examples/libdncp_example.c)
#target_link_libraries(libdncp_example dncp ubox)

# Unit test stuff

# With this, 'make check' works even in a clean tree (sigh, cmake..)
add_custom_target(check COMMAND FAKE_LOG_DISABLE=1 ${CMAKE_CTEST_COMMAND})
enable_testing()
include_directories(src)

add_executable(test_dummy test/test_dummy.c)
add_test(dummy test_dummy)
add_dependencies(check test_dummy)

add_executable(test_tlv test/test_tlv.c ${TLV})
target_link_libraries(test_tlv ubox ${BACKEND_LINK} blobmsg_json)
add_test(tlv test_tlv)
add_dependencies(check test_tlv)

add_executable(test_hncp test/test_hncp.c ${HNCP} ${HT})
target_link_libraries(test_hncp ubox ${BACKEND_LINK} blobmsg_json ${DTLS_LINK})
add_test(hncp test_hncp)
add_dependencies(check test_hncp)

if(${DTLS})
  add_executable(test_dtls test/test_dtls.c ${HT})
  target_link_libraries(test_dtls ${DTLS_LINK} ubox ${BACKEND_LINK} blobmsg_json)
  add_test(dtls test_dtls)
  add_dependencies(check test_dtls)

  add_executable(test_dncp_trust test/test_dncp_trust.c ${HNCP_WITH_GLUE} ${TRUST_SOURCE} ${DTLS_SOURCE} src/udp46.c)
  target_link_libraries(test_dncp_trust ${DTLS_LINK} ubox ${BACKEND_LINK} blobmsg_json)

  add_test(dncp_trust test_dncp_trust)
  add_dependencies(check test_dncp_trust)
endif(${DTLS})

add_executable(test_hncp_io test/test_hncp_io.c ${DTLS_SOURCE} src/udp46.c ${HT})
target_link_libraries(test_hncp_io ubox ${BACKEND_LINK} blobmsg_json ${DTLS_LINK})
add_test(hncp_io test_hncp_io)
add_dependencies(check test_hncp_io)

add_executable(test_exeq test/test_exeq.c)
target_link_libraries(test_exeq ubox)
add_test(exeq test_exeq)
add_dependencies(check test_exeq)

add_executable(test_hncp_net test/test_hncp_net.c ${HNCP_WITH_GLUE})
target_link_libraries(test_hncp_net ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_net test_hncp_net)
add_dependencies(check test_hncp_net)

add_executable(test_hncp_sd test/test_hncp_sd.c src/hncp.c src/hncp_link.c ${DNCP_WITH_PROTO})
target_link_libraries(test_hncp_sd ubox ${BACKEND_LINK} blobmsg_json)
add_test(hncp_sd test_hncp_sd)
add_dependencies(check test_hncp_sd)

#add_executable(test_hncp_multicast test/test_hncp_multicast.c ${HNCP_WITH_GLUE})
#target_link_libraries(test_hncp_multicast ubox ${BACKEND_LINK} blobmsg_json)
#add_test(hncp_multicast test_hncp_multicast)
#add_dependencies(check test_hncp_multicast)

add_executable(test_pa_core test/test_pa_core.c src/pa_rules.c src/pa_filters.c ${BO} ${PX} ${BT})
target_link_libraries(test_pa_core ubox)
add_test(pa_core test_pa_core)
add_dependencies(check test_pa_core)

add_executable(test_pa_filters test/test_pa_filters.c ${BO} ${BT})
target_link_libraries(test_pa_filters ubox)
add_test(pa_filters test_pa_filters)
add_dependencies(check test_pa_filters)

add_executable(test_pa_rules test/test_pa_rules.c src/pa_core.c ${BO} ${PX} ${BT} ${HT})
target_link_libraries(test_pa_rules ubox)
add_test(pa_rules test_pa_rules)
add_dependencies(check test_pa_rules)

add_executable(test_pa_store test/test_pa_store.c ${BO} ${PX} ${BT})
target_link_libraries(test_pa_store ubox)
add_test(pa_store test_pa_store)
add_dependencies(check test_pa_store)

add_executable(test_iface test/test_iface.c ${PU})
target_link_libraries(test_iface ubox)
add_test(iface test_iface)
add_dependencies(check test_iface)

add_executable(test_btrie test/test_btrie.c ${PU})
target_link_libraries(test_btrie ubox)
add_test(btrie test_btrie)
add_dependencies(check test_btrie)

add_executable(test_bitops test/test_bitops.c src/bitops.c)
target_link_libraries(test_bitops)
add_test(bitops test_bitops)
add_dependencies(check test_bitops)

# Historic/non-maintained unit tests

#add_executable(test_hncp_bfs test/test_hncp_bfs.c src/hncp.c ${DNCP_BASE} ${HNCP_IO} ${BT} ${HT})
#target_link_libraries(test_hncp_bfs ubox ${BACKEND_LINK} blobmsg_json ${DTLS_LINK})
#add_test(hncp_bfs test_hncp_bfs)
#add_dependencies(check test_hncp_bfs)

# Packaging rules
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Steven Barth <steven@midlink.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "hnetd")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
