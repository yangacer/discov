cmake_minimum_required (VERSION 2.8)
project (discov)

include ( force_static_msvc_runtime.cmake )

find_package( Boost REQUIRED )

include_directories ( JSON-CC 
                      ${Boost_INCLUDE_DIRS} )
link_directories ( ${PROJECT_SOURCE_DIR} )

add_subdirectory ( JSON-CC )

add_library ( libdiscov discov.cpp )
target_link_libraries ( libdiscov dnssd ws2_32 json )
  
add_executable( discov main.cpp )
target_link_libraries ( discov dnssd ws2_32 libdiscov )

