project(hmac_demo)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(hmac_demo_SRCS
    main.c
)

add_executable(hmac_demo
    ${hmac_demo_SRCS}
)

target_link_libraries(hmac_demo hmac)