#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE base64 test
#include <boost/test/unit_test.hpp>

// g++ -g -O -Wall -Wextra -std=gnu++14 test.cc base64.cpp -lboost_unit_test_framework

#include <string>

#include "base64.h"


// just a dummy function to verify the tests
int base64_throw() {
  throw std::runtime_error("Invalid char in base64url encoded string");
  return 0;
}

std::string rfc[][2] = {
    {"", ""},
    {"f", "Zg=="},
    {"fo", "Zm8="},
    {"foo", "Zm9v"},
    {"foob", "Zm9vYg=="},
    {"fooba", "Zm9vYmE="},
    {"foobar", "Zm9vYmFy"}
};

std::string dns[][2] = {
    {
        // DNS wireframe packet req-microsoft-A.bin
        std::string(
            "\x24\x3A\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x6D\x69\x63"
            "\x72\x6F\x73\x6F\x66\x74\x03\x63\x6F\x6D\x00\x00\x01\x00\x01", 31),
        "JDoBAAABAAAAAAAACW1pY3Jvc29mdANjb20AAAEAAQ=="
    },
    {
        // DNS wireframe packet req-microsoft-AAAA.bin
        std::string(
            "\xDC\xB4\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x6D\x69\x63"
            "\x72\x6F\x73\x6F\x66\x74\x03\x63\x6F\x6D\x00\x00\x1C\x00\x01", 31),
        "3LQBAAABAAAAAAAACW1pY3Jvc29mdANjb20AABwAAQ=="
    },
    {

        std::string(
            "\x24\x3A\x81\x80\x00\x01\x00\x05\x00\x00\x00\x00\x09\x6D\x69\x63"
            "\x72\x6F\x73\x6F\x66\x74\x03\x63\x6F\x6D\x00\x00\x01\x00\x01\xC0"
            "\x0C\x00\x01\x00\x01\x00\x00\x0D\xF5\x00\x04\x68\xD7\x94\x3F\xC0"
            "\x0C\x00\x01\x00\x01\x00\x00\x0D\xF5\x00\x04\x28\x4C\x04\x0F\xC0"
            "\x0C\x00\x01\x00\x01\x00\x00\x0D\xF5\x00\x04\x0D\x4D\xA1\xB3\xC0"
            "\x0C\x00\x01\x00\x01\x00\x00\x0D\xF5\x00\x04\x28\x70\x48\xCD\xC0"
            "\x0C\x00\x01\x00\x01\x00\x00\x0D\xF5\x00\x04\x28\x71\xC8\xC9", 111),        
        "JDqBgAABAAUAAAAACW1pY3Jvc29mdANjb20AAAEAAcAMAAEAAQAADfUABGjXlD_ADAABAAEAAA31"
        "AAQoTAQPwAwAAQABAAAN9QAEDU2hs8AMAAEAAQAADfUABChwSM3ADAABAAEAAA31AAQoccjJ"
    }
};

// testcases from https://gist.github.com/cwgem/1209735
std::string cwgem[][2] = {
    // yeah, this one is actually duplicate to above
    { "", "" },
    { std::string("\0", 1), "AA==" },
    { std::string("\0\0", 2), "AAA=" },
    { std::string("\0\0\0", 3), "AAAA" },
    { "\377", "_w==" },
    { "\377\377", "__8=" },
    { "\377\377\377", "____" },
    // that was a "_+8=" in the original source, which is a bug
    { "\xff\xef", "_-8="},
    { "Send reinforcements", "U2VuZCByZWluZm9yY2VtZW50cw==" },
    {
        "This is line one\nThis is line two\nThis is line three\nAnd so on...\n", 
        "VGhpcyBpcyBsaW5lIG9uZQpUaGlzIGlzIGxpbmUgdHdvClRoaXMgaXMgbGluZSB0aHJlZQpBbmQg"
        "c28gb24uLi4K"
    },
    { "テスト", "44OG44K544OI" }
};

std::string extra[][2] = {
    { "💩",  "8J-SqQ==" } // pile of poo U+1F4A9
};


BOOST_AUTO_TEST_CASE( base64_encode_test_rfc ) 
{
    for(int i=0; i<7; i++)
        BOOST_TEST(base64_encode(rfc[i][0], alphabet::url) == rfc[i][1]);
}
BOOST_AUTO_TEST_CASE( base64_encode_test_dns ) 
{
    for(int i=0; i<3; i++)
        BOOST_TEST(base64_encode(dns[i][0], alphabet::url) == dns[i][1]);
}
BOOST_AUTO_TEST_CASE( base64_encode_test_cwgem ) 
{
    for(int i=0; i<11; i++)
        BOOST_TEST(base64_encode(cwgem[i][0], alphabet::url) == cwgem[i][1]);
}
BOOST_AUTO_TEST_CASE( base64_encode_test_extra ) 
{
    for(int i=0; i<1; i++)
        BOOST_TEST(base64_encode(extra[i][0], alphabet::url) == extra[i][1]);
}

BOOST_AUTO_TEST_CASE( base64_decode_test_rfc ) 
{
    for(int i=0; i<7; i++)
        BOOST_TEST(rfc[i][0] == base64_decode(rfc[i][1], alphabet::url), alphabet::url);
}
BOOST_AUTO_TEST_CASE( base64_decode_test_dns ) 
{
    for(int i=0; i<3; i++)
        BOOST_TEST(dns[i][0] == base64_decode(dns[i][1], alphabet::url), alphabet::url);
}
BOOST_AUTO_TEST_CASE( base64_decode_test_cwgem ) 
{
    for(int i=0; i<11; i++)
        BOOST_TEST(cwgem[i][0] == base64_decode(cwgem[i][1], alphabet::url), alphabet::url);
}
BOOST_AUTO_TEST_CASE( base64_decode_test_extra ) 
{
    for(int i=0; i<1; i++)
        BOOST_TEST(extra[i][0] == base64_decode(extra[i][1], alphabet::url), alphabet::url);
}
BOOST_AUTO_TEST_CASE( base64_exceptions ) 
{
    BOOST_CHECK_THROW( base64_throw(), std::runtime_error);
    BOOST_CHECK_THROW( base64_decode(".", alphabet::url), std::runtime_error);
    BOOST_CHECK_THROW( base64_decode("Zm9vYg==Zm9vYg==", alphabet::url), std::runtime_error);
    BOOST_CHECK_THROW( base64_decode("Zm9vYg=", alphabet::url), std::runtime_error);
}
