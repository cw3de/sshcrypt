// SPDX-License-Identifier: MIT

#pragma once

#include "Data.h"
#include "Debug.h"

#include <iostream>
#include <stdexcept>
#include <string>

inline std::string debugString( int value )
{
  return std::to_string( value );
}
inline std::string debugString( SshCrypt::Size value )
{
  return std::to_string( value );
}
inline std::string debugString( const std::string& value )
{
  return value;
}
inline std::string debugString( const SshCrypt::Data& value )
{
  return SshCrypt::toString( value );
}

#define TEST_VERIFY( condition )                                                               \
  {                                                                                            \
    if( !( condition ) )                                                                       \
    {                                                                                          \
      throw std::runtime_error( std::string( __FILE__ ) + std::string( ":" )                   \
                                + std::to_string( __LINE__ ) + std::string( " in " )           \
                                + std::string( __PRETTY_FUNCTION__ ) );                        \
    }                                                                                          \
  }

#define TEST_COMPARE( x, y )                                                                   \
  {                                                                                            \
    if( ( x ) != ( y ) )                                                                       \
    {                                                                                          \
      throw std::runtime_error(                                                                \
          std::string( __FILE__ ) + std::string( ":" ) + std::to_string( __LINE__ )            \
          + std::string( " in " ) + std::string( __PRETTY_FUNCTION__ ) + std::string( ": " )   \
          + debugString( ( x ) ) + std::string( " != " ) + debugString( ( y ) ) );             \
    }                                                                                          \
  }

#define TEST_RUN( func )                                                                       \
  try                                                                                          \
  {                                                                                            \
    func();                                                                                    \
    std::cout << "PASS " << #func << std::endl;                                                \
  }                                                                                            \
  catch( const std::runtime_error& ex )                                                        \
  {                                                                                            \
    std::cerr << "FAIL " << #func << " : " << ex.what() << std::endl;                          \
    exit( 1 );                                                                                 \
  }
