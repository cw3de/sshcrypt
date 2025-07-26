// SPDX-License-Identifier: MIT

#include "Cryptor.h"

#include "AgentComm.h"
#include "Debug.h"
#include "ShaHash.h"
#include "SymCrypt.h"

#include <cassert>

namespace SshCrypt
{
std::vector<Cryptor::Key> Cryptor::getAvailableKeys()
{
  std::vector<Key> result;
  SshCrypt::AgentComm agent;

  const auto identityList = agent.requestIdentities();
  for( const auto& identity : identityList )
  {
    result.push_back( Key{ toBase64( ShaHash::check( identity.pubkey ), false ),
                           toString( identity.comment ) } );
  }
  return result;
}

Data Cryptor::getSessionKey( const Data& salt, const char* id )
{
  SshCrypt::AgentComm agent;

  const auto identityList = agent.requestIdentities();

  if( identityList.empty() )
  {
    throw std::runtime_error{ "no identities found" };
  }

  SshCrypt::AgentComm::Identity useIdentity;

  if( id )
  {
    for( const auto& identity : identityList )
    {
      auto sha256 = toBase64( ShaHash::check( identity.pubkey ), false );
      LOG_DEBUG( sha256 << " " << SshCrypt::toString( identity.comment ) );
      if( sha256 == id )
      {
        LOG_DEBUG( "identity " << id << " found" );
        useIdentity = identity;
        break;
      }
    }

    if( useIdentity.pubkey.empty() )
    {
      throw std::runtime_error{ "identity not found" };
    }
  }
  else
  {
    useIdentity = identityList.front();
    LOG_DEBUG( "using first identity "
               << toBase64( ShaHash::check( useIdentity.pubkey ), false ) );
  }
  return agent.requestSignature( useIdentity.pubkey, salt );
}

struct PrivateHelper
{
  Data keyiv;
  Data key;
  Data iv;
  SymCrypt aes;

  /*
   * the signature begins with <4 size><x type><4size>
   */
  PrivateHelper( const Data& salt, const char* id ) :
      keyiv{ Cryptor::getSessionKey( salt, id ) },
      key{ keyiv.begin() + 16, keyiv.begin() + 48 }, // first bytes are always the same
      iv{ keyiv.begin() + 48, keyiv.begin() + 64 },
      aes{ key, iv }
  {
    LOG_DEBUG( "salt = " << toHex( salt ) );
    LOG_DEBUG( "Session size = " << keyiv.size() );
    LOG_DEBUG( "key = " << toHex( key ) );
    LOG_DEBUG( "iv = " << toHex( iv ) );
    assert( salt.size() == 32 );
    assert( keyiv.size() >= 64 ); // usually we get 276 bytes
  }
};

Data Cryptor::encrypt( const Data& plainData, const char* id )
{
  Data salt = makeRandom( 32 );
  PrivateHelper helper{ salt, id };
  Data crypedData = helper.aes.encrypt( plainData );

  Data result{ salt }; // salt + encrypted
  result.insert( result.end(), crypedData.begin(), crypedData.end() );
  return result;
}

Data Cryptor::decrypt( const Data& cryptedData, const char* id )
{
  // first 32 bytes of crypedData is the salt
  assert( cryptedData.size() >= 32 );
  Data salt{ cryptedData.begin(), cryptedData.begin() + 32 };
  PrivateHelper helper{ salt, id };
  // const int magiclen = static_cast<int>( helper.magic.size() );
  // Data test{ cryptedData.end() - magiclen, cryptedData.end() };
  // if( test != helper.magic ) { throw std::runtime_error{ "crypted data corrupted" }; }
  return helper.aes.decrypt( Data{ cryptedData.begin() + 32, cryptedData.end() } );
}
} // namespace SshCrypt
