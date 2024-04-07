// SPDX-License-Identifier: MIT
// see https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent

#include "AgentComm.h"

#include "AgentMessage.h"
#include "AgentMessageTypes.h"
#include "Debug.h"

#include <cassert>
#include <fcntl.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace SshCrypt
{
AgentComm::AgentComm( std::string socketName )
{
  if( socketName.empty() )
  {
    socketName = getenv( "SSH_AUTH_SOCK" );
  }

  if( socketName.empty() )
  {
    throw std::runtime_error{ "environment variable SSH_AUTH_SOCK not defined" }; // TODO
  }

  sock = socket( PF_UNIX, SOCK_STREAM, 0 );

  if( sock == -1 )
  {
    throw std::runtime_error{ "can't create unix-domain socket" };
  }

  struct sockaddr_un addr;
  memset( &addr, 0, sizeof addr );
  addr.sun_family = AF_UNIX;
  strcpy( addr.sun_path, socketName.c_str() );
  if( connect( sock, reinterpret_cast<struct sockaddr*>( &addr ), sizeof addr ) == -1 )
  {
    // const int saveError = errno;
    close( sock );
    sock = -1;
    throw std::runtime_error{ "can't connect unix-domain socket" };
  }

  LOG_DEBUG( "socket is open" );
}

AgentComm::~AgentComm()
{
  if( sock != -1 )
  {
    close( sock );
  }
}

AgentMessage AgentComm::sendReceive( const AgentMessage& request )
{
  assert( request.getMessageSize() + 4 == request.getData().size() );

  LOG_DEBUG( "sending " << toHex( request.getData() ) );

  ssize_t w1 = send( sock, request.getData().data(), request.getData().size(), 0 );
  if( w1 == -1 )
  {
    throw std::runtime_error{ "failed to send message" };
  }

  bool haveSize = false;
  Size recvLength = 0;
  AgentMessage response;
  do
  {
    Byte buffer[ 4096 ];
    ssize_t rl = recv( sock, buffer, sizeof buffer, 0 );

    if( rl < 0 )
    {
      throw std::runtime_error{ "recv failed" };
    }

    if( rl == 0 )
    {
      throw std::runtime_error{ "recv returned 0" };
    }

    LOG_DEBUG( "received " << rl << " bytes" );

    response.append( buffer, static_cast<int>( rl ) );

    if( !haveSize && response.getData().size() >= 4 )
    {
      recvLength = response.getMessageSize();
      haveSize = true;
      LOG_DEBUG( "received size: " << recvLength );
    }
  } while( !haveSize || response.getData().size() < ( 4 + recvLength ) );

  LOG_DEBUG( "received " << toHex( response.getData() ) );
  return response;
}

std::vector<AgentComm::Identity> AgentComm::requestIdentities()
{
  std::vector<AgentComm::Identity> idList;
  AgentMessage response = sendReceive( AgentMessage{ SSH_AGENTC_REQUEST_IDENTITIES } );

  if( response.type() != SSH_AGENT_IDENTITIES_ANSWER )
  {
    throw std::runtime_error{ "bad answer, expected identities-answer" };
  }

  Decoder idDecode = response.decoder();
  Size numKeys = idDecode.getInt();

  for( Size i = 0; i < numKeys; ++i )
  {
    const Data keyData = idDecode.getBlobData();
    const Data keyComment = idDecode.getBlobData();

    idList.push_back( Identity{ keyData, keyComment } );
  }

  return idList;
}

Data AgentComm::requestSignature( const Data& pubkey, const Data& data )
{
  AgentMessage signRequest{ SSH_AGENTC_SIGN_REQUEST, 5 + pubkey.size() + data.size() + 4 };
  signRequest.addBlob( pubkey );
  signRequest.addBlob( data );
  signRequest.addInt( SSH_AGENT_RSA_SHA2_256 );
  signRequest.adjustMessageSize();

  AgentMessage response = sendReceive( signRequest );

  if( response.type() != SSH_AGENT_SIGN_RESPONSE )
  {
    throw std::runtime_error{ "bad answer, expected sign-response" };
  }

  Data signature = response.decoder().getBlobData();
  return signature;
}

} // namespace SshCrypt
