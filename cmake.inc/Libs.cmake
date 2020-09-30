function(checkLibExistence NAME TARGET IS_REQUIRED)
	if (EXISTS ${TARGET})
		message("-- Found: lib ${NAME} ${TARGET}")
	else()
		if ( IS_REQUIRED)
			message(FATAL_ERROR "-- Not Found: lib ${NAME} ${TARGET}")
		else()
			message("-- Not Found: lib ${NAME} ${TARGET}")
		endif()
	endif()
endfunction(checkLibExistence)



enable_testing()
find_package(GTest QUIET)
#include_directories(${GTEST_INCLUDE_DIRS})
message("-- GTEST_FOUND: ${GTEST_FOUND} ${GTEST_BOTH_LIBRARIES}")



set(LIB_NAME headerparser)
set(HEADER_PARSER_LIB ${CMAKE_SOURCE_DIR}/build/lib${LIB_NAME}.so)
checkLibExistence(${LIB_NAME} ${HEADER_PARSER_LIB} false)

set(HEADER_PARSER_DEBUG_LIB ${CMAKE_SOURCE_DIR}/build/debug/lib${LIB_NAME}.so)
checkLibExistence(${LIB_NAME} ${HEADER_PARSER_DEBUG_LIB} false)