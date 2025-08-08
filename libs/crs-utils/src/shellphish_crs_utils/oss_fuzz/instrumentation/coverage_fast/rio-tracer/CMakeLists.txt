cmake_minimum_required(VERSION 3.7)

if ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")
  set(DEBUG ON)
endif ("${CMAKE_BUILD_TYPE}" MATCHES "Debug")

project(rio-pompi)
include(CheckIncludeFile)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static")


if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "/workspaces/shellphish-benzene/fun-q-lo-rio/DynamoRIO-Linux-11.3.0-1/cmake" CACHE PATH
    "DynamoRIO installation's cmake directory")
endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

function (add_sample_client name source_file_list extension_list)
  add_library(${name} SHARED ${source_file_list})
  configure_DynamoRIO_client(${name})
  foreach (ext ${extension_list})
    use_DynamoRIO_extension(${name} ${ext})
  endforeach (ext)

  # Provide a hint for how to use the client
  if (NOT DynamoRIO_INTERNAL OR NOT "${CMAKE_GENERATOR}" MATCHES "Ninja")
    DynamoRIO_get_full_path(path ${name} "${location_suffix}")
    add_custom_command(TARGET ${name}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND}
      ARGS -E echo "Usage: pass to drconfig or drrun: -c ${path}"
      VERBATIM)
  endif ()

  get_property(sample_list GLOBAL PROPERTY DynamoRIO_sample_list) # NON-PUBLIC
  set_property(GLOBAL PROPERTY DynamoRIO_sample_list              # NON-PUBLIC
    "${sample_list};${name}")                                     # NON-PUBLIC
  set(srcs ${srcs} ${source_file_list} PARENT_SCOPE)              # NON-PUBLIC
  set(tgts ${tgts} ${name} PARENT_SCOPE)                          # NON-PUBLIC
endfunction (add_sample_client)

# Change .cpp to .c since this is C code
add_sample_client(tracer "tracer.c" "drmgr;drsyms;drutil;drcallstack;drreg;drx;droption")

target_compile_options(tracer PRIVATE 
    -fno-stack-protector 
    -fno-stack-check
    -fno-stack-clash-protection
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(deps REQUIRED IMPORTED_TARGET glib-2.0)
target_link_libraries(tracer PkgConfig::deps)
target_include_directories(tracer PRIVATE ${GLIB2_INCLUDE_DIRS})
target_link_libraries(tracer PRIVATE ${GLIB2_LIBRARIES})

