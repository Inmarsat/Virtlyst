project(Virtlyst)

cmake_minimum_required(VERSION 3.1 FATAL_ERROR)
project(Virtlyst LANGUAGES CXX)
if (POLICY CMP0043)
  cmake_policy(SET CMP0043 NEW)
endif()

if(WIN32)
  if(MSVC)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
  endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(Qt5 COMPONENTS Core Network Sql Xml REQUIRED)
find_package(Cutelyst2Qt5 2.7.0 REQUIRED)
find_package(PkgConfig REQUIRED)
# find_package(Grantlee5 REQUIRED)
find_package(Cutelee5 5.2.0 REQUIRED)

pkg_check_modules(LIBVIRT REQUIRED libvirt)
pkg_check_modules(LIBSSH REQUIRED libssh)

set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

#include_directories(
#    ${CMAKE_SOURCE_DIR}
#    ${CMAKE_CURRENT_BINARY_DIR}
#    ${Cutelyst2Qt5_INCLUDE_DIR}
#)

file(GLOB_RECURSE TEMPLATES_SRC root/*)

add_subdirectory(src)

install(DIRECTORY DESTINATION Virtlyst/data)
install(DIRECTORY root/ DESTINATION Virtlyst/root/)
install(FILES virtlyst DESTINATION /etc/init.d/)

# set(CPACK_PACKAGE_NAME "virtlsyt")
# set(CPACK_PACKAGE_CONTACT "Inmarsat")
# set(CPACK_GENERATOR "")
# set(CPACK_INSTALL_PREFIX "/usr/local")
# set(CPACK_PACKAGING_INSTALL_PREFIX "/usr/local")
# include(CPack)
