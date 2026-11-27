# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.22)
project(fprint_tpm_authenticator VERSION 0.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(FPTA_ENABLE_SANITIZERS "Enable ASan and UBSan for local tests" OFF)
option(FPTA_ENABLE_FUZZING "Build libFuzzer targets (Clang)" OFF)
option(FPTA_BUILD_PROMPT "Build the fpta-prompt window (Qt 6)" ON)

include(GNUInstallDirs)
include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(TSS REQUIRED IMPORTED_TARGET tss2-esys tss2-mu tss2-rc tss2-tctildr)
pkg_check_modules(CBOR REQUIRED IMPORTED_TARGET libcbor)
pkg_check_modules(CRYPTO REQUIRED IMPORTED_TARGET libcrypto)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)

if(FPTA_ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
endif()
add_compile_definitions(_GNU_SOURCE)
add_compile_options(-Wall -Wextra -Wpedantic -Wshadow $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes> -Wformat=2 -Werror
                    -fstack-protector-strong)

configure_file(include/fpta/version.h.in ${CMAKE_BINARY_DIR}/include/fpta/version.h @ONLY)
include_directories(${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include)

add_library(fpta_core STATIC src/ctaphid.c src/ctap2.c src/store.c src/tpm.c)
target_link_libraries(fpta_core PUBLIC PkgConfig::TSS PkgConfig::CBOR PkgConfig::CRYPTO)

add_executable(fptad src/main.c src/uv_fprintd.c)
target_link_libraries(fptad PRIVATE fpta_core PkgConfig::SYSTEMD)

add_executable(fpta-broker src/broker.c)
target_link_libraries(fpta-broker PRIVATE PkgConfig::SYSTEMD)

if(FPTA_BUILD_PROMPT)
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets DBus)
    add_executable(fpta-prompt src/prompt/main.cpp)
    set_target_properties(fpta-prompt PROPERTIES AUTOMOC ON)
    target_compile_definitions(fpta-prompt PRIVATE QT_NO_CAST_FROM_ASCII QT_NO_KEYWORDS)
    target_link_libraries(fpta-prompt PRIVATE Qt6::Widgets Qt6::DBus)
    install(TARGETS fpta-prompt DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/fpta)
    configure_file(packaging/dbus/net.fpta.Prompt.service.in
                   ${CMAKE_BINARY_DIR}/net.fpta.Prompt.service @ONLY)
    configure_file(packaging/systemd/fpta-prompt.service.in
                   ${CMAKE_BINARY_DIR}/fpta-prompt.service @ONLY)
    install(FILES ${CMAKE_BINARY_DIR}/net.fpta.Prompt.service
            DESTINATION ${CMAKE_INSTALL_DATADIR}/dbus-1/services)
    install(FILES ${CMAKE_BINARY_DIR}/fpta-prompt.service DESTINATION lib/systemd/user)
endif()

if(BUILD_TESTING)
    pkg_check_modules(FIDO2 REQUIRED IMPORTED_TARGET libfido2)
    find_program(SWTPM swtpm)

    add_executable(test_ctaphid tests/test_ctaphid.c src/ctaphid.c)
    add_test(NAME ctaphid COMMAND test_ctaphid)

    if(FPTA_BUILD_PROMPT)
        add_test(NAME prompt_render
                 COMMAND ${CMAKE_COMMAND} -E env QT_QPA_PLATFORM=offscreen
                         $<TARGET_FILE:fpta-prompt> --preview 1 ${CMAKE_BINARY_DIR}/prompt-test.png
                         example.com 1 2)
    endif()

    add_executable(test_uv_fprintd tests/test_uv_fprintd.c src/uv_fprintd.c)
    target_link_libraries(test_uv_fprintd PRIVATE PkgConfig::SYSTEMD)
    find_program(DBUS_RUN_SESSION dbus-run-session)
    if(DBUS_RUN_SESSION)
        add_test(NAME fprintd_client
                 COMMAND ${CMAKE_SOURCE_DIR}/tests/run-uv.sh $<TARGET_FILE:test_uv_fprintd>)
        set_tests_properties(fprintd_client PROPERTIES TIMEOUT 120)
    else()
        message(WARNING "dbus-run-session not found: fprintd client test NOT registered")
    endif()

    add_executable(fptad-test src/main.c tests/fake_uv.c)
    target_link_libraries(fptad-test PRIVATE fpta_core)

    add_executable(test_e2e tests/test_e2e.c)
    target_link_libraries(test_e2e PRIVATE PkgConfig::FIDO2 PkgConfig::CBOR PkgConfig::CRYPTO)
    if(SWTPM)
        add_test(NAME e2e_libfido2_swtpm
                 COMMAND ${CMAKE_SOURCE_DIR}/tests/run-e2e.sh ${SWTPM}
                         $<TARGET_FILE:test_e2e> $<TARGET_FILE:fptad-test>)
        set_tests_properties(e2e_libfido2_swtpm PROPERTIES TIMEOUT 120)
    else()
        message(WARNING "swtpm not found: the end-to-end test is NOT registered")
    endif()
endif()

if(FPTA_ENABLE_FUZZING)
    add_executable(fuzz_ctap tests/fuzz_ctap.c src/ctaphid.c src/ctap2.c src/store.c tests/fuzz_stubs.c)
    target_compile_options(fuzz_ctap PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_ctap PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(fuzz_ctap PRIVATE PkgConfig::CBOR PkgConfig::CRYPTO)
endif()

install(TARGETS fptad DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS fpta-broker DESTINATION ${CMAKE_INSTALL_LIBEXECDIR}/fpta)
configure_file(packaging/systemd/fpta-broker.service.in ${CMAKE_BINARY_DIR}/fpta-broker.service @ONLY)
configure_file(packaging/systemd/fptad.service.in ${CMAKE_BINARY_DIR}/fptad.service @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/fpta-broker.service packaging/systemd/fpta-broker.socket
        DESTINATION lib/systemd/system)
install(FILES ${CMAKE_BINARY_DIR}/fptad.service DESTINATION lib/systemd/user)
install(FILES packaging/modules-load.conf DESTINATION lib/modules-load.d RENAME fpta.conf)
install(PROGRAMS tools/hw-check.sh DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME fpta-hw-check)
install(PROGRAMS tools/security-check.sh DESTINATION ${CMAKE_INSTALL_BINDIR} RENAME fpta-security-check)
install(FILES man/fptad.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
install(FILES README.md SECURITY.md CHANGELOG.md docs/ARCHITECTURE.md docs/TESTING.md
        DESTINATION ${CMAKE_INSTALL_DATADIR}/doc/fprint-tpm-authenticator)
