cmake_minimum_required(VERSION 3.16)
project(swap-kms-sdk-local-e2e LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The official Nitro SDK helper runs on Linux; use the documented builder container")
endif()

# Compile exactly the production helper against the same pinned AWS libraries.
# The executable wrappers and runtime NSM replacement exist only in this project.
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../enclave/kms-tool" production-helper)
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
