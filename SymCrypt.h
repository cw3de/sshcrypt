// SPDX-License-Identifier: MIT

#pragma once

#include "Data.h"

// aus <openssl/ossl_typ.h>
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

namespace SshCrypt
{
class SymCrypt
{
public:
  enum Method
  {
    AES256CBC
  };

  SymCrypt( const Data& key, const Data& iv, Method method = Method::AES256CBC );
  ~SymCrypt();

  Data encrypt( const Data& plainData ) const;
  Data decrypt( const Data& encryptedData ) const;

private:
  const Method method = Method::AES256CBC;
  const Data key;
  const Data iv;
  const EVP_CIPHER* cipher = nullptr;
  EVP_CIPHER_CTX* ctx = nullptr;

  void privateInit();
};

} // namespace SshCrypt
