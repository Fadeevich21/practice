# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY  https://github.com/google/googletest.git
    GIT_TAG         f8d7d77                                     # v1.14.0
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

file(GLOB TEST_FILES "${PROJECT_SOURCE_DIR}/tests/*.cpp")
foreach(TEST_PATH ${TEST_FILES})
    get_filename_component(EXECUTABLE_NAME ${TEST_PATH} NAME_WE)
    add_executable(${EXECUTABLE_NAME}_tests ${TEST_PATH})
    target_link_libraries(${EXECUTABLE_NAME}_tests GTest::gtest_main)
    target_include_directories(${EXECUTABLE_NAME}_tests PRIVATE ${PROJECT_SOURCE_DIR}/include)
    gtest_discover_tests(${EXECUTABLE_NAME}_tests)
endforeach()
