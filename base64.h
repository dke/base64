#ifndef LOWDOH_BASE64_H
#define LOWDOH_BASE64_H

#include <string>

enum alphabet { plain, url };

std::string base64_encode(const std::string &, enum alphabet a=plain);
std::string base64_decode(const std::string &, enum alphabet a=plain);

#endif
