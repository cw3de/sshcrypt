// SPDX-License-Identifier: MIT

// ssh agent uses network byte order (big endian)

#include "AgentMessage.h"

#include <stdexcept>

namespace SshCrypt
{
Data Decoder::int2net( Size value ) // static
{
  Data data;
  data.push_back( static_cast<Byte>( ( value >> 24 ) & 0xff ) );
  data.push_back( static_cast<Byte>( ( value >> 16 ) & 0xff ) );
  data.push_back( static_cast<Byte>( ( value >> 8 ) & 0xff ) );
  data.push_back( static_cast<Byte>( value & 0xff ) );
  return data;
}

Size Decoder::net2int( const Byte* buffer ) // static
{
  Size value;
  value = static_cast<Size>( buffer[ 0 ] ) << 24 | static_cast<Size>( buffer[ 1 ] ) << 16
          | static_cast<Size>( buffer[ 2 ] ) << 8 | static_cast<Size>( buffer[ 3 ] );

  return value;
}

Size Decoder::getInt()
{
  if( bytesLeft() < 4 )
    throw std::runtime_error{ "truncated message: need 4 bytes for an int" };

  Size value = net2int( data + pos );
  pos += 4;
  return value;
}

//! return the next blob as data
Data Decoder::getBlobData()
{
  Size length = getInt();
  if( length > bytesLeft() )
    throw std::runtime_error{ "truncated message: blob size greater than blob" };

  const Byte* b = data + pos;
  const Byte* e = data + pos + length;
  pos += length;
  return Data{ b, e };
}

//! return the next blob as a new decoder
Decoder Decoder::getDataDecoder()
{
  Size length = getInt();
  if( length > bytesLeft() )
    throw std::runtime_error{ "truncated message: blob size greater than blob" };

  const Byte* b = data + pos;
  // const Byte* e = data + pos + length;
  pos += length;
  return Decoder{ b, length };
}

/*! \class AgentMessage
 *
 * 0..3 size of message not including the size itself
 * 4..4 message type
 * 5... payload
 */

//! new message for sending \a type
AgentMessage::AgentMessage( Byte type, Size reserveBytes )
{
  if( reserveBytes )
    data.reserve( reserveBytes );

  data.resize( 5, 0 );
  data[ 4 ] = type;
  adjustMessageSize();
}
Byte AgentMessage::type() const
{
  if( data.size() >= 5 )
    return data[ 4 ];
  return 0;
}

//! must be called after last addInt() or addBlob()
void AgentMessage::adjustMessageSize()
{
  Data sizeData = Decoder::int2net( data.size() - 4 );
  data[ 0 ] = sizeData[ 0 ];
  data[ 1 ] = sizeData[ 1 ];
  data[ 2 ] = sizeData[ 2 ];
  data[ 3 ] = sizeData[ 3 ];
}

void AgentMessage::addInt( Size value )
{
  append( Decoder::int2net( value ) );
}

void AgentMessage::addBlob( const Data& blob )
{
  append( Decoder::int2net( blob.size() ) );
  append( blob );
}

//! append bytes for new messages
void AgentMessage::append( const Data& bytes )
{
  data.insert( std::end( data ), std::begin( bytes ), std::end( bytes ) );
}

//! append bytes received from socket
void AgentMessage::append( const Byte* values, int size )
{
  data.reserve( static_cast<Size>( size ) );
  while( size-- > 0 )
  {
    data.push_back( *values++ );
  }
}

} /* namespace SshCrypt */
