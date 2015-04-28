project(hmac)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(hmac_SRCS
    sha1.c
    sha2.c
    hmac_sha1.c
    hmac_sha2.c
)

add_library(hmac
    ${hmac_SRCS}
)

set(INS_TARGETS
    hmac
)

# Install
install(TARGETS ${INS_TARGETS}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)
