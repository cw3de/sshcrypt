// SPDX-License-Identifier: MIT

#include "Data.h"

#include <cassert>
#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>

namespace SshCrypt
{
std::string toString( const Data& bytes )
{
  return std::string( std::begin( bytes ), std::end( bytes ) );
}

Data fromString( const std::string& text )
{
  return Data( std::begin( text ), std::end( text ) );
}

std::string toHex( const Data& bytes, const char* separator )
{
  static const char hexdigit[] = "0123456789abcdef";
  static_assert( sizeof hexdigit == 17, "16 hexdigits" );

  bool first = true;
  std::stringstream str;
  for( Byte val : bytes )
  {
    if( first )
      first = false;
    else if( separator )
      str << separator;

    str << hexdigit[ ( val >> 4 ) & 0xf ];
    str << hexdigit[ val & 0xf ];
  }
  return str.str();
}

/* Base 64 from wikipedia:
 *
 * Use A-Z, a-z, 0-9, '+' and '/' as digits, fill with '='.
 *
 * |    Byte 1     |    Byte 2     |    Byte 3     |
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 *
 * |5|4|3|2|1|0|5|4|3|2|1|0|5|4|3|2|1|0|5|4|3|2|1|0|
 * |  Char 1   |  Char 2   |  Char 3   |  Char 3   |
 */

std::string toBase64( const Data& bytes, bool padding )
{
  static const char base64digit[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    "abcdefghijklmnopqrstuvwxyz"
                                    "0123456789+/";
  static_assert( sizeof base64digit == 65, "64 base64 digits" );
  constexpr unsigned int mask = 0x3fu;

  /*
   * Ori Pad NoPad
   * 0   0   0
   * 1   4   2
   * 2   4   3
   * 3   4   4
   * 4   8   6
   * 5   8   8
   */
  Size base64Length;
  if( padding )
  {
    base64Length = ( ( ( ( bytes.size() + 2 ) ) / 3 ) * 4 );
  }
  else
  {
    base64Length = bytes.size() / 3 * 4;
    switch( bytes.size() % 3 )
    {
    case 0: break;
    case 1: base64Length += 2; break;
    case 2: base64Length += 3; break;
    }
  }
  std::string result( base64Length, '=' );
  size_t pos = 0;
  int bits = 0;
  Size accu = 0;

  for( auto b : bytes )
  {
    accu = ( accu << 8 ) | ( b & 0xffu );
    bits += 8;
    while( bits >= 6 )
    {
      bits -= 6;
      result[ pos++ ] = base64digit[ ( accu >> bits ) & mask ];
    }
  }
  if( bits > 0 )
  {
    assert( bits < 6 );
    accu <<= ( 6 - bits );
    result[ pos++ ] = base64digit[ accu & mask ];
  }

  return result;
}

Data fromBase64( const std::string& ascii )
{
#define XX 64
  static const Byte asciiTable[ 128 ]
      = { XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,   // 0x00-0x0f
          XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX,   // 0x10-0x1f
          XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, XX, 62, XX, XX, XX, 63,   // 0x20-0x2f
          52, 53, 54, 55, 56, 57, 58, 59, 60, 61, XX, XX, XX, XX, XX, XX,   // 0x30-0x3f
          XX, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,   // 0x40-0x4f
          15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, XX, XX, XX, XX, XX,   // 0x50-0x5f
          XX, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,   // 0x60-0x6f
          41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, XX, XX, XX, XX, XX }; // 0x70-0x7f

  auto maximumLength = ascii.size() * 3 / 4 + 1;
  Data result;
  result.reserve( maximumLength );
  int bits = 0;
  Size accu = 0;

  for( int c : ascii )
  {
    if( std::isspace( c ) || c == '=' )
      continue;
    if( c < 0x2b || c > 0x7a || asciiTable[ c ] > 63 )
      throw std::invalid_argument{ "illegal character" };

    accu = ( accu << 6 ) | asciiTable[ c ];
    bits += 6;
    if( bits >= 8 )
    {
      bits -= 8;
      result.push_back( ( accu >> bits ) & 0xffu );
    }
  }
  return result;
}

Data makeRandom( Size size, Byte min, Byte max )
{
  Data data;
  data.resize( size );

  std::mt19937 randomEngine;
  randomEngine.seed( static_cast<std::mt19937::result_type>(
      std::chrono::system_clock::now().time_since_epoch().count() ) );

  std::uniform_int_distribution<Byte> randomDistribution{ min, max };
  for( Size pos = 0; pos < size; ++pos )
  {
    data[ pos ] = randomDistribution( randomEngine );
  }

  return data;
}

Data loadFile( const char* filename, ReadMode readMode )
{
  if( !filename )
  {
    return readData( std::cin, readMode );
  }
  std::ifstream file{ filename };
  return readData( file, readMode );
}

Data readData( std::istream& in, ReadMode readMode )
{
  std::istreambuf_iterator<char> iter( in.rdbuf() );
  std::istreambuf_iterator<char> eos;
  Data data{ iter, eos };
  switch( readMode )
  {
  case ReadMode::Raw: break;
  case ReadMode::Base64: data = fromBase64( toString( data ) ); break;
  case ReadMode::Auto:
    try
    {
      return fromBase64( toString( data ) );
    }
    catch( const std::invalid_argument& )
    {
      // return data
    }
    break;
  }
  return data;
}

void saveFile( const Data& data, const char* filename, WriteMode writeMode )
{
  if( !filename )
  {
    return writeData( data, std::cout, writeMode );
  }
  std::ofstream file{ filename };
  writeData( data, file, writeMode );
}

void writeData( const Data& data, std::ostream& out, WriteMode writeMode )
{
  switch( writeMode )
  {
  case WriteMode::Raw:
  {
    std::ostreambuf_iterator<char> outIter( out );
    std::copy( data.begin(), data.end(), outIter );
  }
  break;
  case WriteMode::Base64:
  {
    std::string base64 = toBase64( data );
    int len = 0;
    for( auto c : base64 )
    {
      out << c;
      ++len;
      if( len >= 72 )
      {
        out << std::endl;
        len = 0;
      }
    }
    if( len )
    {
      out << std::endl;
    }
  }
  break;
  }
}

} /* namespace SshCrypt */
