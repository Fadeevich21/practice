set(CMAKE_EXPORT_COMPILE_COMMANDS True)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

file(GLOB TEST_FILES "${PROJECT_SOURCE_DIR}/test/*.cpp")
foreach(TEST_PATH ${TEST_FILES})
    get_filename_component(EXECUTABLE_NAME ${TEST_PATH} NAME_WE)
    add_executable(${EXECUTABLE_NAME} ${TEST_PATH})
    target_link_libraries(${EXECUTABLE_NAME} GTest::gtest_main)
    gtest_discover_tests(${EXECUTABLE_NAME})
endforeach()
