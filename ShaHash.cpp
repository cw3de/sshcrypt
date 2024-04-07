// SPDX-License-Identifier: MIT

#include "ShaHash.h"

#include "Debug.h"

#include <openssl/evp.h>
#include <stdexcept>

namespace SshCrypt
{
Data ShaHash::check( const Data& data )
{
  auto sha256 = EVP_get_digestbyname( "sha256" );
  if( !sha256 )
  {
    LOG_DEBUG( "no sha256" );
    throw std::runtime_error( "no sha256" );
  }
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if( !ctx )
  {
    LOG_DEBUG( "no ctx" );
    throw std::runtime_error( "no ctx" );
  }
  if( EVP_DigestInit_ex2( ctx, sha256, nullptr ) != 1 )
  {
    LOG_DEBUG( "no init" );
    throw std::runtime_error( "no init" );
  }
  if( EVP_DigestUpdate( ctx, data.data(), data.size() ) != 1 )
  {
    LOG_DEBUG( "no update" );
    throw std::runtime_error( "no update" );
  }
  Data sum;
  sum.resize( EVP_MAX_MD_SIZE );
  unsigned int len = 0;
  if( EVP_DigestFinal_ex( ctx, sum.data(), &len ) != 1 )
  {
    LOG_DEBUG( "no final" );
    throw std::runtime_error( "no final" );
  }
  EVP_MD_CTX_free( ctx );
  sum.resize( len );
  return sum;
}

} // namespace SshCrypt
