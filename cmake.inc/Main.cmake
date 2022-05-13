set(HEADER_PARSER headerParser)
add_executable(
	${HEADER_PARSER}
	src/headerParser.c
#	src/utils/fifo/Fifo.c
	)
target_sources(${HEADER_PARSER} PRIVATE
	${HEADER_PARSER_SRC}
	)

set(LIB_NAME headerparser)
set(HEADER_PARSER_SO ${HEADER_PARSER}_so)
add_library(${HEADER_PARSER_SO} SHARED ${HEADER_PARSER_LIB_FILES})
#set_target_properties(${HEADER_PARSER_SO} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${HEADER_PARSER_SO} PROPERTIES OUTPUT_NAME ${LIB_NAME})
set_target_properties(${HEADER_PARSER_SO} PROPERTIES POSITION_INDEPENDENT_CODE ON)

#set(STATIC_LIB headerparser_static)
#add_library(${STATIC_LIB} STATIC ${HEADER_PARSER_LIB_FILES})
#set_target_properties(${STATIC_LIB} PROPERTIES VERSION ${PROJECT_VERSION})
##set_target_properties(${STATIC_LIB} PROPERTIES PUBLIC_HEADER include/utils/)
#set_target_properties(${STATIC_LIB} PROPERTIES OUTPUT_NAME ${LIB_NAME})
#set_target_properties(${STATIC_LIB} PROPERTIES POSITION_INDEPENDENT_CODE ON)
