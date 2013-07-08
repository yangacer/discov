cmake_minimum_required (VERSION 2.8)
project (discov)

include ( force_static_msvc_runtime.cmake )

link_directories ( ${PROJECT_SOURCE_DIR} )

add_library ( libdiscov discov.cpp )
target_link_libraries ( libdiscov dnssd ws2_32 )
  
add_executable( discov main.cpp )
target_link_libraries ( discov dnssd ws2_32 libdiscov )

