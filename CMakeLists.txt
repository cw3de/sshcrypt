# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.7.0)
project( sshcrypt )
set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_CXX_STANDARD_REQUIRED True )

enable_testing()

set( EXTRA_WARNINGS
    -Werror
    -Wall
    -Wextra
    -Wpedantic 
)

find_package( OpenSSL REQUIRED )

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_DEBUG_MACRO")

set( HEADERS
  AgentComm.h
  AgentMessage.h
  AgentMessageTypes.h
  Cryptor.h
  Data.h
  Debug.h
  ShaHash.h
  SymCrypt.h
)

set( SOURCES
  AgentComm.cpp
  AgentMessage.cpp
  Cryptor.cpp
  Data.cpp
  ShaHash.cpp
  SymCrypt.cpp
)

add_executable( sshcrypt
  SshCrypt.cpp
  ${HEADERS}
  ${SOURCES}
)

target_link_libraries( sshcrypt
  PUBLIC
  OpenSSL::Crypto
)

target_include_directories( sshcrypt
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  OPENSSL_INCLUDE_DIR
)

target_compile_options( sshcrypt
  PUBLIC
  ${EXTRA_WARNINGS}
)


########################################################


add_executable( testsshcrypt
  TestSshCrypt.cpp
  ${HEADERS}
  ${SOURCES}
)

target_link_libraries( testsshcrypt
  PUBLIC
  OpenSSL::Crypto
  )

target_include_directories( testsshcrypt
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  )

target_compile_options( testsshcrypt
  PUBLIC
    ${EXTRA_WARNINGS}
  )
  
add_test( NAME testsshcrypt COMMAND testsshcrypt )


