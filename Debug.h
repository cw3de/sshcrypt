// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>

#if defined( ENABLE_DEBUG_MACRO )
#define LOG_DEBUG( ... )                                                                       \
  do                                                                                           \
  {                                                                                            \
    std::cout << "DEBUG: " << __VA_ARGS__ << std::endl;                                        \
  } while( false )
#else
#define LOG_DEBUG( ... )
#endif

#define LOG_INFO( ... )                                                                        \
  do                                                                                           \
  {                                                                                            \
    std::cout << "INFO: " << __VA_ARGS__ << std::endl;                                         \
  } while( false )

#define LOG_ERROR( ... )                                                                       \
  do                                                                                           \
  {                                                                                            \
    std::cerr << "ERROR: " << __VA_ARGS__ << std::endl;                                        \
  } while( false )
