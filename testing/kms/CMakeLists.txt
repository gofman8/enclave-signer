cmake_minimum_required(VERSION 3.16)
project(swap-kms-sdk-local-e2e LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The official Nitro SDK helper runs on Linux; use the documented builder container")
endif()

# Compile exactly the production helper against the same pinned AWS libraries.
# The executable wrappers and runtime NSM replacement exist only in this project.
find_package(json-c CONFIG REQUIRED)
if(NOT TARGET LibJsonC::Json)
  add_library(LibJsonC::Json ALIAS json-c::json-c)
endif()
find_package(aws-nitro-enclaves-sdk-c CONFIG REQUIRED)
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../enclave/kms-tool" production-helper)
# Upstream's static export records libnsm as an absolute build-time path.
# Resolve only that shared library again when mounting the identical dependency
# prefix elsewhere in the test container. The SDK objects remain unchanged.
find_library(NSM_LINK_LIBRARY NAMES nsm REQUIRED)
get_target_property(SDK_LINK_LIBRARIES AWS::aws-nitro-enclaves-sdk-c INTERFACE_LINK_LIBRARIES)
set(RELOCATED_SDK_LINK_LIBRARIES "")
foreach(LINK_LIBRARY IN LISTS SDK_LINK_LIBRARIES)
  get_filename_component(LINK_NAME "${LINK_LIBRARY}" NAME)
  if(LINK_NAME STREQUAL "libnsm.so")
    list(APPEND RELOCATED_SDK_LINK_LIBRARIES "${NSM_LINK_LIBRARY}")
  else()
    list(APPEND RELOCATED_SDK_LINK_LIBRARIES "${LINK_LIBRARY}")
  endif()
endforeach()
set_target_properties(AWS::aws-nitro-enclaves-sdk-c PROPERTIES
  INTERFACE_LINK_LIBRARIES "${RELOCATED_SDK_LINK_LIBRARIES}")
target_sources(swap-kms-tool PRIVATE "${CMAKE_CURRENT_LIST_DIR}/sdk-test-adapter.c")
target_link_options(swap-kms-tool PRIVATE
  "-Wl,--wrap=aws_nitro_enclaves_rest_client_new"
  "-Wl,--wrap=aws_tls_ctx_options_init_default_client"
  "-Wl,--wrap=ioctl")
set_target_properties(swap-kms-tool PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

find_path(NSM_INCLUDE_DIR nsm.h REQUIRED)
add_library(mock-nsm SHARED "${CMAKE_CURRENT_LIST_DIR}/mock-nsm.c")
target_include_directories(mock-nsm PRIVATE "${NSM_INCLUDE_DIR}")
target_compile_options(mock-nsm PRIVATE -Wall -Wextra -Werror)
set_target_properties(mock-nsm PROPERTIES
  OUTPUT_NAME nsm
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/mock")
