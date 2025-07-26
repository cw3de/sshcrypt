// SPDX-License-Identifier: MIT

#pragma once
#include "Data.h"

namespace SshCrypt
{
class Cryptor
{
public:
  Cryptor() = delete;

  struct Key
  {
    std::string sha256;
    std::string comment;
  };

  static std::vector<Key> getAvailableKeys();
  static Data getSessionKey( const Data& salt, const char* id );
  static Data encrypt( const Data&, const char* id = nullptr );
  static Data decrypt( const Data&, const char* id = nullptr );
};
} // namespace SshCrypt
