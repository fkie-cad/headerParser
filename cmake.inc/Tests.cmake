if ( ${GTEST_FOUND} )

	set(G_TESTS_DIR tests)

	set(HEADER_PARSER_TEST_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/utils/FileUtil.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/utils/StringUtil.h

		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/jar/JarParserTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/pe/PEParserTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/utils/ConverterTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/utils/HelperTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/HeaderParserTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/HeaderParserLibTest.h
		${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/HeaderParserLibPETest.h
		)

#	set(ENV{LSAN_OPTIONS} verbosity=1:log_threads=1)
	set(UNIT_TEST_SUITE headerParser_tests)

	add_executable(
		${UNIT_TEST_SUITE}
		${G_TESTS_DIR}/unitTests.cpp
		${HEADER_PARSER_SRC}
		${HEADER_PARSER_TEST_FILES}
	)
	add_dependencies(${UNIT_TEST_SUITE} ${HEADER_PARSER})
	add_dependencies(${UNIT_TEST_SUITE} ${HEADER_PARSER_SO})

	set_target_properties(${UNIT_TEST_SUITE} PROPERTIES
		CXX_STANDARD 17
		CXX_STANDARD_REQUIRED YES
		CXX_EXTENSIONS NO
		LANGUAGES CXX
#		COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Werror=return-type -Werror=overflow -Werror=format"
#		COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer"
#		COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fno-omit-frame-pointer"
		LINK_FLAGS "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address -fsanitize=leak"
		)

	target_link_libraries(${UNIT_TEST_SUITE} PRIVATE
		${GTEST_BOTH_LIBRARIES}
		optimized ${HEADER_PARSER_LIB}
		debug ${HEADER_PARSER_DEBUG_LIB}
		)

	add_test(
		cTests
		${UNIT_TEST_SUITE}
	)

endif()

#add_executable(compareResultToObjDump tests/compareResultToObjDump.c )

add_executable(testHeaderParserLib tests/testHeaderParserLib.c )
target_link_libraries(testHeaderParserLib PRIVATE
	optimized ${HEADER_PARSER_LIB}
	debug ${HEADER_PARSER_DEBUG_LIB}
	)
add_dependencies(testHeaderParserLib ${HEADER_PARSER_SO})


add_executable(testHeaderParserLibPE tests/testHeaderParserLibPE.c)
target_link_libraries(testHeaderParserLibPE PRIVATE
	optimized ${HEADER_PARSER_LIB}
	debug ${HEADER_PARSER_DEBUG_LIB}
	)
add_dependencies(testHeaderParserLibPE ${HEADER_PARSER_SO})


add_executable(
	HPDirectoryRunner
	${G_TESTS_DIR}/HPDirectoryRunner.cpp
	${G_TESTS_DIR}/misc/DirectoryRunner.cpp
	${G_TESTS_DIR}/misc/DirectoryRunner.h
	${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/RawHeaderDataParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/utils/FileUtil.h
	${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/utils/StringUtil.h
)
set_target_properties(HPDirectoryRunner PROPERTIES
	CXX_STANDARD 17
	CXX_STANDARD_REQUIRED YES
	CXX_EXTENSIONS NO
	LANGUAGES CXX
	COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pedantic -Werror=return-type -Werror=overflow -Werror=format -D_FILE_OFFSET_BITS=64"
#	COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=leak -fsanitize=undefined -fno-omit-frame-pointer"
	LINK_FLAGS "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize=undefined -fno-omit-frame-pointer"
	)
target_link_libraries(HPDirectoryRunner PRIVATE
	stdc++fs
	optimized ${HEADER_PARSER_LIB}
	debug ${HEADER_PARSER_DEBUG_LIB}
	${CMAKE_CURRENT_SOURCE_DIR}/${G_TESTS_DIR}/misc/libutils_full.so
	)
add_dependencies(HPDirectoryRunner ${HEADER_PARSER} ${HEADER_PARSER_SO})