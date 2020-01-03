#include <string>
#include <vector>
#include <stdexcept>

#include "base64.h"

/*
Based on https://gist.github.com/0f96e1d313e1d0da5051e1a6eff8d329.git
which seems to be public domain
I did a review, did some index shifts, variables renaming for better 
understandability, add padding and padding verification for the decode function
*/

/*
Base64 translates 24 bits into 4 ASCII characters at a time. First,
3 8-bit bytes are treated as 4 6-bit groups. Those 4 groups are
translated into ASCII characters. That is, each 6-bit number is treated
as an index into the ASCII character array.

If the final set of bits is less 8 or 16 instead of 24, traditional base64
would add a padding character. However, if the length of the data is
known, then padding can be eliminated.

One difference between the "standard" Base64 is two characters are different.
See RFC 4648 for details.
This is how we end up with the Base64 URL encoding.
*/

static const unsigned char base64_alphabet[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const unsigned char base64_url_alphabet[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_";

// map the values above to their index
// map '=' to \x40 and everyting else to \xff
static const unsigned char base64_alphabet_reverse[] =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff\xff\x3f"
    "\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\x40\xff\xff"
    "\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
    "\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\xff"
    "\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28"
    "\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

static const unsigned char base64_url_alphabet_reverse[] =
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" // 00..0F
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" // 10..1F
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x3e\xff\xff" // 20..2F
    "\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\xff\xff\xff\x40\xff\xff" // 30..3F
    "\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e" // etc.
    "\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\xff\xff\xff\xff\x3f"
    "\xff\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28"
    "\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

// so we shift with each iteration one byte from the input buffer
// (== to be encoded bytes) into the "accumulator"
// and for every 6-bit-"nibble" we have, we push it into the output
// buffer (or, rather, its encoded value by lookup from the
// base64_url_alphabet table). Usually this will be one nibble,
// but sometimes (every four times) it will be two nibbles.
std::string base64_encode(const std::string & in, enum alphabet a) {
    const unsigned char *alphabet=(a==url?base64_url_alphabet:base64_alphabet);
    std::string out;
    int accu=0; // accumulator
    int index=0; // how many valid (but not yet outputted) bits are in the accumulator
    size_t len = in.length();
    bool contains_real_data = true; // are we in the "real data" section, or in the "padded zeroes" section?
    // for loop end condition: continue as long as we either are still in the real data section, or in the "padded zeroes" section
    for (unsigned i = 0; i < len || index!=0; i++) {
        // rotate one byte into the accumulator, thus, keeping any existing stuff 
        accu = (accu<<8) + (i<len?static_cast<unsigned char>(in[i]):0);
        index += 8;
        while (index >= 6) {
            index -= 6;
            // now index is how many bits are to the right of the 6-nibble which is to be output
            // thus, the 6 bits we need to output are the least significant bits of (accu>>index)
            // 0x3F is 0b111111, thus, a bitmask to get the 6-nibble
            out.push_back(contains_real_data?(alphabet[(accu>>index)&0x3F]):'=');
            // if i==len (which implies index was !=0 at the loop head ), we have just output
            // the last nibble which contains real data (leftover bits from the last byte, where i==len-1)
            // everything else will be padding zeros, which are output as '='
            if(i==len) contains_real_data=false;
        }
    }
    return out;
}

// same spirit as above.
std::string base64_decode(const std::string & in, enum alphabet a) {
  const unsigned char *reverse_alphabet=(a==url?base64_url_alphabet_reverse:base64_alphabet_reverse);
  bool in_padding=false;
  std::string out;
  // accumulator
  int accu = 0;
  // how many valid bits are in the accumulator
  int index = 0;
  if (in.length() % 4) {
    // we should have padding to always be blocks for 4 chars
    throw std::runtime_error("base64 encoded string length not dividable by 4");
  }
  for (unsigned i = 0; i < in.length(); i++) {
    unsigned char c = in[i];
    if (reverse_alphabet[c] == 0xff) {
      // invalid char. we should fail reasonably
      throw std::runtime_error("Invalid char in base64url encoded string");
    }
    if (reverse_alphabet[c] == 0x40) {
      in_padding=true;
      continue;
    }
    if (in_padding) {
      throw std::runtime_error("Non-padding char after padding char encountered");      
    }
    accu = (accu<<6) + reverse_alphabet[c];
    index += 6;
    if (index >= 8) {
      index -= 8;
      out.push_back(char((accu>>index)&0xFF));
    }
  }
  return out;
}

#if 0
#include <iostream>
#include <iomanip>

void print_inverse_table() {
  static std::vector<u_int8_t> T(256, 255);
  for (unsigned i =0; i < 64; i++) T[base64_alphabet[i]] = i;
  T['=']=0x40;

  for(u_int8_t i: T) {
    std::cout << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)i;
  }
  std::cout << std::endl;
}
#endif