// SPDX-License-Identifier: MIT

#pragma once

#include <iostream>
#include <string>
// #include <tuple>
#include <vector>

namespace SshCrypt
{
enum class ReadMode
{
  Raw,
  Base64,
  Auto
};

enum class WriteMode
{
  Raw,
  Base64,
};

using Byte = unsigned char;
using Data = std::vector<Byte>;
using Size = Data::size_type;

std::string toString( const Data& );
std::string toHex( const Data&, const char* separator = nullptr );
std::string toBase64( const Data&, bool padding = true );
Data makeRandom( Size size, Byte min = 0, Byte max = 0xffu );
Data fromString( const std::string& );
Data fromBase64( const std::string& );
Data loadFile( const char* filename, ReadMode mode = ReadMode::Auto );
Data readData( std::istream&, ReadMode mode = ReadMode::Auto );
void saveFile( const Data&, const char* filename, WriteMode mode = WriteMode::Raw );
void writeData( const Data&, std::ostream&, WriteMode mode = WriteMode::Raw );

inline std::ostream& operator<<( std::ostream& out, const Data& bytes )
{
  for( Byte b : bytes )
  {
    if( b < 32 || b > 126 )
    {
      out << '<' << static_cast<int>( b ) << '>';
    }
    else
    {
      out << static_cast<char>( b );
    }
  }
  return out;
}

} // namespace SshCrypt
