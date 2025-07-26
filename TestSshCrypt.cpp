// SPDX-License-Identifier: MIT

#include "AgentMessage.h"
// #include "Cryptor.h"
#include "Debug.h"
#include "ShaHash.h"
#include "SymCrypt.h"
#include "TestMacros.h"

namespace SshCrypt
{
void test_Data()
{
  const char testdata[] = "dideldadeldum";
  const auto* a = &testdata[ 0 ];
  const auto* b = &testdata[ sizeof testdata ];
  Data data{ a, b };
}

void test_Hex()
{
  Data data = fromString( "ABCDEFGHIJKLMNOP" );
  LOG_DEBUG( "no space: " << toHex( data ) );
  TEST_COMPARE( toHex( data ), "4142434445464748494a4b4c4d4e4f50" );
  LOG_DEBUG( "separated: " << toHex( data, "," ) );
  TEST_COMPARE( toHex( data, "," ), "41,42,43,44,45,46,47,48,49,4a,4b,4c,4d,4e,4f,50" );
}

void test_Base64()
{
  TEST_COMPARE( toBase64( fromString( "1" ), true ), "MQ==" );
  TEST_COMPARE( toBase64( fromString( "1" ), false ), "MQ" );

  TEST_COMPARE( toBase64( fromString( "12" ), true ), "MTI=" );
  TEST_COMPARE( toBase64( fromString( "12" ), false ), "MTI" );

  TEST_COMPARE( toBase64( fromString( "123" ), true ), "MTIz" );
  TEST_COMPARE( toBase64( fromString( "123" ), false ), "MTIz" );

  TEST_COMPARE( toBase64( fromString( "1234" ), true ), "MTIzNA==" );
  TEST_COMPARE( toBase64( fromString( "1234" ), false ), "MTIzNA" );

  TEST_COMPARE( toBase64( fromString( "12345" ), true ), "MTIzNDU=" );
  TEST_COMPARE( toBase64( fromString( "12345" ), false ), "MTIzNDU" );

  Data original
      = fromString( "Polyfon zwitschernd aßen Mäxchens Vögel Rüben, Joghurt und Quark" );
  LOG_DEBUG( "original: " << toString( original ) );

  std::string base64 = toBase64( original );
  LOG_DEBUG( "base64: " << base64 );

  TEST_COMPARE( base64,
                "UG9seWZvbiB6d2l0c2NoZXJuZCBhw59lbiBNw6R4Y2hlbnMgVsO2Z2VsIFLDvGJlbiwgSm9naHVydC"
                "B1bmQgUXVhcms=" );

  auto back = fromBase64( base64 );
  LOG_DEBUG( "back: " << toString( back ) );
  TEST_COMPARE( original, back );

  auto dummy = fromBase64( "+/AMZaxz059=" );
  LOG_DEBUG( "dummy: " << toHex( dummy ) );
  TEST_COMPARE( toHex( dummy ), "fbf00c65ac73d39f" );
}

void test_SaveLoad()
{
  const char testFilename[] = "/tmp/test-ssh-crypt.dat";
  Data testData = makeRandom( 240 );
  saveFile( testData, testFilename, WriteMode::Raw );

  Data load1auto = loadFile( testFilename );
  TEST_COMPARE( testData, load1auto );

  saveFile( testData, testFilename, WriteMode::Base64 );
  Data load2base64 = loadFile( testFilename, ReadMode::Base64 );
  TEST_COMPARE( testData, load2base64 );

  Data load2auto = loadFile( testFilename, ReadMode::Auto );
  TEST_COMPARE( testData, load2auto );

  // read base64 as raw does not give the same result
  Data load2raw = loadFile( testFilename, ReadMode::Raw );
  TEST_VERIFY( testData != load2raw );
}

void test_AgentMessage()
{
  AgentMessage ba0;
  TEST_COMPARE( ba0.getData().size(), 0 );

  AgentMessage ba1{ 0x01 };
  TEST_COMPARE( ba1.getData().size(), 5 );
  TEST_COMPARE( ba1.getMessageSize(), 1 );

  ba1.addInt( 4711 );
  ba1.adjustMessageSize();
  TEST_COMPARE( ba1.getData().size(), 9 );
  TEST_COMPARE( ba1.getMessageSize(), 5 );
}

void test_SymCrypt()
{
  Data key = fromString( "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" );
  Data iv = fromString( "ABCDEFGHIJKLMNOP" );

  LOG_DEBUG( "key= " << toHex( key ) );
  LOG_DEBUG( "iv= " << toHex( iv ) );
  SymCrypt crypt{ key, iv };

  Data original = fromString( "Dideldadeldum" );
  LOG_DEBUG( "original: " << original );

  Data crypted = crypt.encrypt( original );
  LOG_DEBUG( "crypted: " << toHex( crypted ) );

  // echo -n "Dideldadeldum" | openssl aes-256-cbc -e -K hex(key) -iv hex(iv) -base64
  TEST_COMPARE( toBase64( crypted ), "TBQpM/Q9YRhw7AY/fBdMiw==" );

  Data plain = crypt.decrypt( crypted );
  LOG_DEBUG( "plain: " << plain );
}

void test_ShaHash()
{
  Data data = fromString( "ABCDEFGHIJKLMNOP" );
  Data sha256sum = ShaHash::check( data );
  std::string hex = toHex( sha256sum );
  TEST_COMPARE( hex, "e7e8b89c2721d290cc5f55425491ecd6831355e91063f20b39c22f9ec6a71f91" );
}

} // namespace SshCrypt

int main( int, char** )
{
  TEST_RUN( SshCrypt::test_Data );
  TEST_RUN( SshCrypt::test_Hex );
  TEST_RUN( SshCrypt::test_Base64 );
  TEST_RUN( SshCrypt::test_SaveLoad );
  TEST_RUN( SshCrypt::test_AgentMessage );
  TEST_RUN( SshCrypt::test_SymCrypt );
  TEST_RUN( SshCrypt::test_ShaHash );
}
