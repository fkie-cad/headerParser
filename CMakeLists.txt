cmake_minimum_required(VERSION 3.10)
project(HeaderParser VERSION 1.15.5 DESCRIPTION "A PE, ELF and other types header parser" LANGUAGES C)

if (WIN32)
    message("No cmake support on Windows. Use msbuild and winBuild.bat.")
    return()
endif()

set(LANGUAGE C)
#set(CMAKE_C_STANDARD 90)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -Werror=return-type -Werror=overflow -Werror=format -D_FILE_OFFSET_BITS=64")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Wl,-z,relro,-z,now -fno-builtin -Wall -pedantic  -Werror=return-type -Werror=overflow -D_FILE_OFFSET_BITS=64 -Ofast")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer")
#	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined") # multiple times occuring due to raw bytes casting,  etc.
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=thread") # not compatilbe to leak
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=memory") # unrecognized

set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=leak")
#	set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")


message("DEBUG_PRINT : ${DEBUG_PRINT}")
if (DEBUG_PRINT)
    add_definitions(-DDEBUG_PRINT=${DEBUG_PRINT})
endif()

message("CMAKE_FLAGS_DEBUG : ${CMAKE_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_DEBUG : ${CMAKE_C_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_RELEASE : ${CMAKE_C_FLAGS_RELEASE}")
message("CMAKE_FLAGS_RELEASE : ${CMAKE_FLAGS_RELEASE}")
message("CMAKE_EXE_LINKER_FLAGS : ${CMAKE_EXE_LINKER_FLAGS}")

include(cmake.inc/Libs.cmake)
include(cmake.inc/Sources.cmake)
include(cmake.inc/Main.cmake)

if ( ${GTEST_FOUND} )
	include(cmake.inc/Res.cmake)
	enable_language(CXX)
	include(cmake.inc/Tests.cmake)
endif()

#add_executable(
#	compareToObjDump
#	tests/compareResultToObjDump.c
#	pe/PECoffCharacteristics.h)
