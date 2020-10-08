cmake_minimum_required(VERSION 3.16)
project(WPA2 C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(src)

set(PROJECT_HEADERS src/wpa2_specific_hmac.h src/wpa2_specific_sha1.h src/pbkdf2/pbkdf2.h src/pbkdf2/pbkdf2_specific_hmac.h
        src/pbkdf2/pbkdf2_specific_sha1.h cap2hccapx/cap2hccapx.h)

set(PROJECT_SOURCES main.c src/wpa2_specific_hmac.c src/wpa2_specific_sha1.c src/pbkdf2/pbkdf2.c src/pbkdf2/pbkdf2_specific_hmac.c
        src/pbkdf2/pbkdf2_specific_sha1.c cap2hccapx/cap2hccapx.c src/types/sha1_types.h)

add_executable(WPA2 ${PROJECT_SOURCES} ${PROJECT_HEADERS})