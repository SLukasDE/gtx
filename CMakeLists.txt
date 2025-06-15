cmake_minimum_required(VERSION 3.23)

project(
    gtx
    VERSION 1.0.0
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src/main)

install(TARGETS gtx
        EXPORT gtx-export
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

install(EXPORT      gtx-export
        FILE        gtxTargets.cmake
        NAMESPACE   gtx::
        DESTINATION lib/cmake
)

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/gtxConfig.cmake
        DESTINATION "lib/cmake"
)
