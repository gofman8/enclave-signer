cmake_minimum_required(VERSION 3.18)
project(swap-kms-native-tests C)

# The SDK's installed export names LibJsonC::Json but does not discover it.
# Alias the installed json-c package instead of borrowing SDK Find modules.
find_package(json-c CONFIG REQUIRED)
if(NOT TARGET LibJsonC::Json)
    add_library(LibJsonC::Json ALIAS json-c::json-c)
endif()
find_package(aws-nitro-enclaves-sdk-c CONFIG REQUIRED)
# The production build installs the pinned upstream header verbatim.
find_path(NITRO_SDK_INCLUDE_DIR aws/nitro_enclaves/internal/cms.h REQUIRED)

function(configure_helper_target target)
    target_link_options(${target} PRIVATE "-Wl,--wrap=aws_client_bootstrap_new")
    target_compile_features(${target} PRIVATE c_std_11)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -Wpedantic)
    target_include_directories(${target} PRIVATE "${NITRO_SDK_INCLUDE_DIR}")
    target_link_libraries(${target} PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
endfunction()

include(CTest)
if(BUILD_TESTING)
    add_executable(swap-kms-tool-input-tests input_cleanup.c)
    configure_helper_target(swap-kms-tool-input-tests)
    add_test(NAME credential-cleanup COMMAND swap-kms-tool-input-tests)

    add_executable(swap-kms-tool-response-tests response_contract.c)
    configure_helper_target(swap-kms-tool-response-tests)
    add_test(NAME response-contract COMMAND swap-kms-tool-response-tests)

    # Real CRT signing and transport, without failure wrappers: a peer closes
    # before request activation, just as a relay can during Recipient creation.
    add_executable(swap-kms-sdk-closed-connection-tests closed_connection.c)
    target_compile_options(swap-kms-sdk-closed-connection-tests PRIVATE -Wall -Wextra -Werror -Wpedantic)
    target_link_libraries(swap-kms-sdk-closed-connection-tests PRIVATE AWS::aws-nitro-enclaves-sdk-c LibJsonC::Json)
    add_test(NAME sdk-closed-generate-bounded COMMAND swap-kms-sdk-closed-connection-tests TrentService.GenerateDataKey)
    add_test(NAME sdk-closed-decrypt-bounded COMMAND swap-kms-sdk-closed-connection-tests TrentService.Decrypt)
    set_tests_properties(sdk-closed-generate-bounded sdk-closed-decrypt-bounded PROPERTIES TIMEOUT 20)
endif()
