// SPDX-License-Identifier: MIT

#include "Cryptor.h"
#include "Debug.h"

#include <exception>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>

static void usage( const char* programName )
{
  std::cout
      << "usage: " << programName << " <operation> [-b] [-k key] [inputfile [outputfile]]\n"
      << "  -d,  --decrypt     decrypt input to output\n"
      << "  -e,  --encrypt     encrypt input to ouput\n"
      << "  -v,  --edit        decrypt, edit, encrypt\n"
      << "  -b,  --binary      encrypt as binary, base64 encoded otherweise\n"
      << "  -k,  --key=SHA256  use key with SHA256 checksum, first one found otherweise\n"
      << "  -l,  --listkeys    list available keys\n"
      << "\n"
      << "If outputfile is omitted, the result is written to stdout.\n"
      << "If inputfile is omitted, the input is read from stdin.\n"
      << "If no key is given, the key is read from the environment variable SSHCRYPT_KEY.\n"
      << "Set EDITOR environment variable to change the editor used by the -v option.\n"
      << std::endl;
}

static SshCrypt::Data magicWord{ 'S', 's', 'H', 'c', 'R', 'y', 'P', 't' };

static void encryptFile( const char* inputFilename,
                         const char* outputFilename,
                         const char* forceKey,
                         SshCrypt::WriteMode writeMode )
{
  auto plainData = SshCrypt::loadFile( inputFilename, SshCrypt::ReadMode::Raw );
  // append magic word, so we can check it on decrypt
  plainData.insert( plainData.end(), magicWord.begin(), magicWord.end() );
  auto cryptedData = SshCrypt::Cryptor::encrypt( plainData, forceKey );
  SshCrypt::saveFile( cryptedData, outputFilename, writeMode );
}

static void decryptFile( const char* inputFilename,
                         const char* outputFilename,
                         const char* forceKey,
                         SshCrypt::WriteMode )
{
  auto cryptedData = SshCrypt::loadFile( inputFilename, SshCrypt::ReadMode::Auto );
  auto plainData = SshCrypt::Cryptor::decrypt( cryptedData, forceKey );
  if( plainData.size() < magicWord.size() )
  {
    throw std::runtime_error{ "invalid input (too short)" };
  }
  const auto magicTest = SshCrypt::Data{ plainData.end() - magicWord.size(), plainData.end() };
  if( magicTest != magicWord )
  {
    throw std::runtime_error{ "invalid input (bad magic)" };
  }
  plainData.erase( plainData.end() - magicWord.size(), plainData.end() );
  SshCrypt::saveFile( plainData, outputFilename, SshCrypt::WriteMode::Raw );
}

static bool editFile( const char* filename )
{
  const char* editor = getenv( "EDITOR" );
  if( !editor )
    editor = "vi";
  std::ostringstream command;
  command << editor << " " << filename;

  int rc = system( command.str().c_str() );
  return rc == 0;
}

// RAII class for temporary files
class TemporaryFile
{
public:
  TemporaryFile()
  {
    int fd = mkstemp( tempFilename );
    if( fd == -1 )
    {
      throw std::runtime_error{ "can't create temporary file" };
    }
  }

  ~TemporaryFile()
  {
    // always remove the file
    remove( tempFilename );
  }

  const char* name() const { return tempFilename; }

private:
  char tempFilename[ 256 ] = "/tmp/.secretXXXXXX";
};

int main( int argc, char** argv )
{
  try
  {
    enum class Operation
    {
      Usage,
      ListKeys,
      Encrypt,
      Decrypt,
      Editor,
    };
    Operation operation = Operation::Usage;
    SshCrypt::WriteMode writeMode = SshCrypt::WriteMode::Base64;
    const char* forceKey = getenv( "SSHCRYPT_KEY" );

    static struct option sshCryptOptions[] = { { "binary", no_argument, nullptr, 'b' },
                                               { "decrypt", no_argument, nullptr, 'd' },
                                               { "encrypt", no_argument, nullptr, 'e' },
                                               { "edit", no_argument, nullptr, 'v' },
                                               { "key", required_argument, nullptr, 'k' },
                                               { "listkeys", no_argument, nullptr, 'l' },
                                               { nullptr, 0, nullptr, 0 } };
    int optionIndex = 0;

    int opt;
    while( ( opt = getopt_long( argc, argv, "bedk:lv", sshCryptOptions, &optionIndex ) ) != -1 )
    {
      switch( opt )
      {
      case 'b': writeMode = SshCrypt::WriteMode::Raw; break;
      case 'd': operation = Operation::Decrypt; break;
      case 'e': operation = Operation::Encrypt; break;
      case 'v': operation = Operation::Editor; break;
      case 'l': operation = Operation::ListKeys; break;
      case 'k': forceKey = optarg; break;
      default: usage( argv[ 0 ] ); exit( 2 );
      }
    }

    const char* inputFilename = optind < argc ? argv[ optind++ ] : nullptr;
    const char* outputFilename = optind < argc ? argv[ optind++ ] : nullptr;
    if( optind != argc )
      throw std::runtime_error{ "too many arguments" };

    if( operation == Operation::Editor )
    {
      if( !inputFilename )
        throw std::runtime_error{ "edit needs inputfile" };
      if( !outputFilename )
        outputFilename = inputFilename;
    }

    switch( operation )
    {
    case Operation::Usage: usage( argv[ 0 ] ); break;
    case Operation::ListKeys:
    {
      const auto keys = SshCrypt::Cryptor::getAvailableKeys();
      for( const auto& key : keys )
      {
        std::cout << key.sha256 << " " << key.comment << std::endl;
      }
    }
    break;
    case Operation::Encrypt:
      encryptFile( inputFilename, outputFilename, forceKey, writeMode );
      break;
    case Operation::Decrypt:
      decryptFile( inputFilename, outputFilename, forceKey, writeMode );
      break;
    case Operation::Editor:
    {
      TemporaryFile tempFile;
      decryptFile( inputFilename, tempFile.name(), forceKey, writeMode );
      if( editFile( tempFile.name() ) )
      {
        encryptFile( tempFile.name(), outputFilename, forceKey, writeMode );
      }
    }
    break;
    }
  }
  catch( const std::exception& ex )
  {
    std::cerr << "exception: " << ex.what() << std::endl;
  }
}
