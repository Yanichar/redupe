cmake_minimum_required(VERSION 3.8)

project(Redupe)

add_executable(redupe redupe.c redupe-cli.c)
target_include_directories(redupe PUBLIC include)
target_link_libraries(redupe popt)
target_link_libraries(redupe m)