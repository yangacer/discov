cmake_minimum_required (VERSION 2.8)
project (discov)

link_directories ( ${PROJECT_SOURCE_DIR} )

add_executable( discov main.cpp )
target_link_libraries ( discov dnssd ws2_32)
