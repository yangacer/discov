cmake_minimum_required (VERSION 2.8)
project (discov)

include ( JSON-CC/use_c++11.cmake )
include ( force_static_msvc_runtime.cmake )

find_package( Boost REQUIRED )

include_directories ( JSON-CC 
                      ${Boost_INCLUDE_DIRS} )

link_directories ( ${PROJECT_SOURCE_DIR} )

add_subdirectory ( JSON-CC )

if( MSVC )
  set ( DEPEND_LIB ws2_32 dnssd )
endif()

add_library ( libdiscov discov.cpp )
target_link_libraries ( libdiscov ${DEPEND_LIB} json )
  
add_executable( discov main.cpp )
target_link_libraries ( discov ${DEPEND_LIB} libdiscov )

