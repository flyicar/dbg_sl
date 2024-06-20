cmake_minimum_required (VERSION 3.0)
project (Debbuger)

add_compile_options(-std=c++14)

include_directories(ext/libelfin ext/linenoise include)
add_executable(dbg src/dbg.cpp ext/linenoise/linenoise.c)

add_executable(example ex/ex.cpp)
set_target_properties(example
                      PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0")

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)
target_link_libraries(dbg
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(dbg libelfin)