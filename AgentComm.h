// SPDX-License-Identifier: MIT
#pragma once

#include "AgentMessage.h"

#include <string>
#include <vector>

namespace SshCrypt
{
class AgentComm
{
public:
  struct Identity
  {
    Data pubkey;
    Data comment;
  };

  AgentComm( std::string socketName = std::string{} );
  ~AgentComm();
  AgentMessage sendReceive( const AgentMessage& request );

  std::vector<Identity> requestIdentities();
  Data requestSignature( const Data& pubkey, const Data& data );

private:
  int sock = -1;
};
} // namespace SshCrypt
