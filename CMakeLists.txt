cmake_minimum_required(VERSION 3.15)
project(sfparse C)

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(SFPARSE_ENABLE_INSTALL "Enable install" OFF)

include(GNUInstallDirs)

add_library(sfparse sfparse.c sfparse.h)
add_library(sfparse::sfparse ALIAS sfparse)

set(DEFINITIONS)
list(APPEND DEFINITIONS SFPARSE_BUILDING)
if(NOT BUILD_SHARED_LIBS)
    list(APPEND DEFINITIONS SFPARSE_STATIC)
endif()
target_compile_definitions(sfparse PRIVATE ${DEFINITIONS})
target_include_directories(sfparse PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

if(SFPARSE_ENABLE_INSTALL)
    install(
        FILES "${CMAKE_CURRENT_LIST_DIR}/sfparse.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/sfparse"
    )
    install(TARGETS sfparse EXPORT sfparse)
    install(
        EXPORT sfparse
        NAMESPACE sfparse::
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/sfparse"
    )
endif()
