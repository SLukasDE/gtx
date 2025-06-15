include(FetchContent)

message(STATUS "Try to find OpenESL by FetchContent")
#set(OPENESL_USE_COMMON4ESL OFF)
FetchContent_Declare(
    openesl
    GIT_REPOSITORY https://github.com/slukasde/OpenESL
    #GIT_TAG        v1.6.0
    GIT_SHALLOW    TRUE
    OVERRIDE_FIND_PACKAGE # 'find_package(...)' will call 'FetchContent_MakeAvailable(...)'
)
find_package(openesl REQUIRED)

file(GLOB_RECURSE ${PROJECT_NAME}_SRC ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

#add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
if (BUILD_SHARED_LIBS)
    message(STATUS "-> lib type is SHARED")
    add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_SRC})
else (BUILD_SHARED_LIBS)
    message(STATUS "-> lib type is STATIC")
    add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_SRC})
endif (BUILD_SHARED_LIBS)

add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC
    openesl::openesl)
