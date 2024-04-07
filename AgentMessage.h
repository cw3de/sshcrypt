// SPDX-License-Identifier: MIT

#pragma once

#include "Data.h"

namespace SshCrypt
{
class Decoder
{
public:
  static Size net2int( const Byte* buffer );
  static Data int2net( Size value );

  Decoder() = default;
  Decoder( const Decoder& ) = default;
  Decoder& operator=( const Decoder& ) = default;
  Decoder( Decoder&& ) = default;
  Decoder& operator=( Decoder&& ) = default;

  Decoder( const Byte* theData, Size theSize ) : data{ theData }, size{ theSize } {}
  Decoder( const Data& theData ) : data{ theData.data() }, size{ theData.size() } {}
  Size bytesLeft() const { return size - pos; }
  Size getInt();
  Data getBlobData();
  Decoder getDataDecoder();

private:
  const Byte* data = nullptr;
  Size size = 0;
  Size pos = 0;
};

class AgentMessage
{
public:
  AgentMessage() = default;
  AgentMessage( Byte type, Size reserveBytes = 0 );

  Byte type() const;
  const Data& getData() const { return data; }

  // receiving
  void append( const Byte*, int size );
  Size getMessageSize() const { return Decoder::net2int( data.data() ); }
  Decoder decoder() const { return Decoder{ data.data() + 5, data.size() - 5 }; }

  // building
  void addInt( Size );
  void addBlob( const Data& );
  void adjustMessageSize();

private:
  Data data;
  void append( const Data& );
};

} /* namespace SshCrypt */
