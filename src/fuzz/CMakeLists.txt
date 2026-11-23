# minIni fuzz harness. Configured by fuzzer/lib/build.sh, one build dir per
# variant; every instrumentation flag comes from afl-cc's AFL_USE_* env vars.
#
#   fuzz      the campaign binary (afl-cc, libAFLDriver via -fsanitize=fuzzer)
#   fuzz2     reproducer: RR()/RF() + file replay, no engine, asan+ubsan
#             (FUZZ_REPRO_SANITIZER=memory: msan)
#   fuzz_cov  coverage: no engine, no sanitizer, -fprofile-instr-generate
cmake_minimum_required(VERSION 3.13)
project(minini_fuzz C)

get_filename_component(MININI_DEV "${CMAKE_CURRENT_SOURCE_DIR}/../../dev" ABSOLUTE)

# minIni.c and minIni.h include "minGlue.h" from their own directory first, so
# the fuzz glue only wins if they sit next to it: copy all three into the build tree. The
# #line keeps debug info, sanitizer stacks and coverage on dev/minIni.c.
set(GLUE_DIR ${CMAKE_BINARY_DIR}/minini)
file(READ ${MININI_DEV}/minIni.c MININI_SRC)
file(WRITE ${GLUE_DIR}/minIni.c "#line 1 \"${MININI_DEV}/minIni.c\"\n${MININI_SRC}")
configure_file(${MININI_DEV}/minIni.h ${GLUE_DIR}/minIni.h COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/minGlue.h ${GLUE_DIR}/minGlue.h COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/fuzz_vfs.h ${GLUE_DIR}/fuzz_vfs.h COPYONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${MININI_DEV}/minIni.c ${MININI_DEV}/minIni.h ${CMAKE_CURRENT_SOURCE_DIR}/minGlue.h ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_vfs.h)

# NDEBUG stays undefined: minIni.c's assert()s are oracles.
set(BASE_OPTS -g -O2 -fno-omit-frame-pointer -D_GNU_SOURCE)
set(FUZZ_INCLUDES ${GLUE_DIR})

set(FUZZ_REPRO_SANITIZER "address" CACHE STRING "fuzz2 sanitizer: address or memory")
if(FUZZ_REPRO_SANITIZER STREQUAL "address")
    set(REPRO_SAN -fsanitize=address,undefined -fno-sanitize-recover=all)
elseif(FUZZ_REPRO_SANITIZER STREQUAL "memory")
    set(REPRO_SAN -fsanitize=memory -fsanitize-memory-track-origins=2)
else()
    message(FATAL_ERROR "FUZZ_REPRO_SANITIZER must be address or memory")
endif()

function(harness name)
    cmake_parse_arguments(A "" "" "OPTIONS;LINK" ${ARGN})
    add_executable(${name} ${CMAKE_CURRENT_SOURCE_DIR}/main.c)
    target_include_directories(${name} PRIVATE ${FUZZ_INCLUDES})
    target_compile_options(${name} PRIVATE ${BASE_OPTS} ${A_OPTIONS})
    target_link_options(${name} PRIVATE ${A_LINK} -rdynamic)
    target_link_libraries(${name} PRIVATE ${CMAKE_DL_LIBS})
endfunction()

harness(fuzz     LINK -fsanitize=fuzzer)
harness(fuzz2    OPTIONS -O0 -DREPRODUCER ${REPRO_SAN} LINK ${REPRO_SAN})
harness(fuzz_cov OPTIONS -DREPRODUCER -fprofile-instr-generate -fcoverage-mapping
                 LINK -fprofile-instr-generate)
