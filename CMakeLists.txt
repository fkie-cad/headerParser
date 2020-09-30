cmake_minimum_required(VERSION 3.10)
project(HeaderParser VERSION 1.0.9 DESCRIPTION "A PE and ELF header parser" LANGUAGES C)

set(CMAKE_C_STANDARD 90)
if (UNIX)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -Werror=return-type")
	set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG -Wl,-z,relro,-z,now -fno-builtin -Werror=return-type -D_FILE_OFFSET_BITS=64 -Ofast")

	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer")
#	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined") # multiple times occuring due to raw bytes casting,  etc.
	#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=thread") # not compatilbe to leak
	#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=memory") # unrecognized

	set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=leak")
#	set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")
endif (UNIX)
if (WIN32)
	SET(CMAKE_C_FLAGS "/nologo /Zi /GS /INCREMENTAL /W4 /MP /GS /Gy /guard:cf /we4715 /we4716 ${CMAKE_C_FLAGS}") # /WX
	SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} /DEBUG /Od /MDd")
	SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} /DNDEBUG /O2 /MD")

	string( TOLOWER "${MT}" mt )

	if (mt STREQUAL "debug")
		message("/MTd")
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
		SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MTd")
	elseif (mt STREQUAL "release")
		message("/MT")
		SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MT")
		SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
	endif()
	
#	SET(CMAKE_EXE_LINKER_FLAGS "/INCREMENTAL ${CMAKE_EXE_LINKER_FLAGS}")
	SET(CMAKE_EXE_LINKER_FLAGS "/NXCOMPAT /guard:cf ${CMAKE_EXE_LINKER_FLAGS}")
	SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
	SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "/DYNAMICBASE ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
	if (PDB EQUAL 1)
		SET(CMAKE_EXE_LINKER_FLAGS_RELEASE "/DEBUG ${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
	endif()

	IF (CMAKE_CL_32)
		SET(CMAKE_EXE_LINKER_FLAGS "/SAFESEH ${CMAKE_EXE_LINKER_FLAGS}")
	ENDIF (CMAKE_CL_32)

	message("CMAKE_C_FLAGS is ${CMAKE_C_FLAGS_RELEASE}")
	message("CMAKE_EXE_LINKER_FLAGS is ${CMAKE_EXE_LINKER_FLAGS}")
endif (WIN32)


message("CMAKE_FLAGS_DEBUG : ${CMAKE_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_DEBUG} : ${CMAKE_C_FLAGS_DEBUG}")
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
