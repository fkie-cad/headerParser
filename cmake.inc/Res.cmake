set(TEST_FILES_SRC tests/files/ )
set(TEST_FILES_DEST tests/files/ )
file(COPY ${TEST_FILES_SRC} DESTINATION ./${TEST_FILES_DEST})