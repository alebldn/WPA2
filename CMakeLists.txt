cmake_minimum_required(VERSION 3.16)
project(WPA2 C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(src)

set(PROJECT_HEADERS src/sha1.h src/hmac.h src/pbkdf2.h cap2hccapx/cap2hccapx.h)

set(PROJECT_SOURCES main.c src/sha1.c src/hmac.c src/pbkdf2.c cap2hccapx/cap2hccapx.c)

add_executable(WPA2 ${PROJECT_SOURCES} ${PROJECT_HEADERS})