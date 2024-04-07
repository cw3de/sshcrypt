// SPDX-License-Identifier: MIT

#include "SymCrypt.h"

#include "Debug.h"

#include <openssl/evp.h>
#include <stdexcept>

namespace SshCrypt
{
SymCrypt::SymCrypt( const Data& theKey, const Data& theIv, Method theMethod ) :
    method{ theMethod }, key{ theKey }, iv{ theIv }, ctx{ EVP_CIPHER_CTX_new() }
{
  privateInit();
}

SymCrypt::~SymCrypt()
{
  EVP_CIPHER_CTX_free( ctx );
}

void SymCrypt::privateInit()
{
  if( !ctx )
  {
    throw std::runtime_error{ "EVP_CIPHER_CTX_new() failed" };
  }

  switch( method )
  {
  case SymCrypt::Method::AES256CBC:
    cipher = EVP_aes_256_cbc();
    break;
    // default: throw std::runtime_error{ "unknown cipher" };
  }

  if( static_cast<int>( key.size() ) != EVP_CIPHER_key_length( cipher ) )
  {
    LOG_ERROR( "size of key is " << key.size() << ", but must be "
                                 << EVP_CIPHER_key_length( cipher ) );

    throw std::runtime_error{ "bad key size" };
  }
  if( static_cast<int>( iv.size() ) != EVP_CIPHER_iv_length( cipher ) )
  {
    LOG_ERROR( "size of iv is " << iv.size() << ", but must be "
                                << EVP_CIPHER_iv_length( cipher ) );
    throw std::runtime_error{ "bad iv size" };
  }
}

Data SymCrypt::encrypt( const Data& plainData ) const
{
  const int blockSize = EVP_CIPHER_block_size( cipher );
  const int resultLength
      = static_cast<int>( plainData.size() )
        + ( blockSize - ( static_cast<int>( plainData.size() ) % blockSize ) );
  Data encryptedData;
  encryptedData.resize( static_cast<Size>( resultLength ), 0 );

  if( !EVP_EncryptInit_ex( ctx, cipher, nullptr, key.data(), iv.data() ) )
  {
    throw std::runtime_error{ "EVP_EncryptInit_ex() failed" };
  }

  int encryptLength = 0;
  if( !EVP_EncryptUpdate( ctx,
                          encryptedData.data(),
                          &encryptLength,
                          plainData.data(),
                          static_cast<int>( plainData.size() ) ) )
  {
    throw std::runtime_error{ "EVP_EncryptUpdate() failed" };
  }

  int paddingLength = 0;
  if( !EVP_EncryptFinal_ex( ctx, encryptedData.data() + encryptLength, &paddingLength ) )
  {
    throw std::runtime_error{ "EVP_EncryptFinal_ex() failed" };
  }

  const int totalLength = encryptLength + paddingLength;
  if( totalLength != resultLength )
    abort();

  return encryptedData;
}

Data SymCrypt::decrypt( const Data& encryptedData ) const
{
  Data decryptedData;
  decryptedData.resize( encryptedData.size(), 0 );

  if( !EVP_DecryptInit_ex( ctx, cipher, nullptr, key.data(), iv.data() ) )
  {
    throw std::runtime_error{ "EVP_DecryptInit_ex() failed" };
  }

  int decryptLength = 0;
  if( !EVP_DecryptUpdate( ctx,
                          decryptedData.data(),
                          &decryptLength,
                          encryptedData.data(),
                          static_cast<int>( encryptedData.size() ) ) )
  {
    throw std::runtime_error{ "EVP_DecryptUpdate() failed" };
  }

  int paddingLength = 0;
  if( !EVP_DecryptFinal_ex( ctx, decryptedData.data() + decryptLength, &paddingLength ) )
  {
    throw std::runtime_error{ "EVP_DecryptFinal_ex() failed" };
  }

  const int totalLength = decryptLength + paddingLength;
  if( totalLength > static_cast<int>( encryptedData.size() ) )
    abort();

  decryptedData.resize( static_cast<Size>( totalLength ) );
  return decryptedData;
}

} // namespace SshCrypt
