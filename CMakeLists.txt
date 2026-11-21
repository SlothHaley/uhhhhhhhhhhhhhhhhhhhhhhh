cmake_minimum_required(VERSION 3.5)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(foldertrace C)
include("${VITASDK}/share/vita.cmake" REQUIRED)

# Plugins are built without the standard startup code or libc (-nostdlib).
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -O2 -std=gnu99 -nostdlib -fno-builtin -fno-tree-loop-distribute-patterns -fno-stack-protector")

add_executable(foldertrace src/plugin.c)
set_target_properties(foldertrace PROPERTIES LINK_FLAGS "-nostdlib")

# Stub library names differ between SDK versions, so link whichever exist.
set(STUBLIB_DIR "${VITASDK}/arm-vita-eabi/lib")
set(OPTIONAL_STUBS
  SceKernelThreadMgr_stub
  SceKernelModulemgr_stub
  SceThreadmgr_stub
  SceModulemgr_stub
)
set(FOUND_STUBS "")
foreach(lib ${OPTIONAL_STUBS})
  if(EXISTS "${STUBLIB_DIR}/lib${lib}.a")
    list(APPEND FOUND_STUBS ${lib})
  endif()
endforeach()
message(STATUS "Optional stubs found: ${FOUND_STUBS}")
file(GLOB ALL_STUBS "${STUBLIB_DIR}/libSce*Thread*.a" "${STUBLIB_DIR}/libSce*Module*.a" "${STUBLIB_DIR}/libSce*Process*.a")
message(STATUS "Thread/Module/Process stub libs in SDK: ${ALL_STUBS}")

target_link_libraries(foldertrace
  taihen_stub
  SceLibKernel_stub
  SceIofilemgr_stub
  SceProcessmgr_stub
  ${FOUND_STUBS}
  gcc
)

vita_create_self(foldertrace.suprx foldertrace CONFIG exports.yml UNSAFE)
