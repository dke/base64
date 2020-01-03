#include <iostream>
#include <vector>

#include "base64.h"

// testcase
// shell code
/*
testcase() {
    dd if=/dev/urandom of=random bs=1 count=$RANDOM
    cat random | ./base64 | sha256sum
    cat random | base64 -w 0 | sha256sum
    cat random | ./base64 | ./base64 -d | sha256sum
    cat random | base64 -w 0 | base64 -d | sha256sum
    cat random | sha256sum
}
*/

enum mode { encode, decode };
int main(int argc, char **argv) {
    // a multiple of 3 to avoid padding on block boundaries
    const unsigned buffer_size=3*1024;
    std::vector<char> buffer;
    buffer.reserve(buffer_size);

    mode m=mode::encode;
    alphabet a = alphabet::plain;
    bool add_newline=false;

    // poor man's argument parsing
    for(int i=1; i<argc; i++) {
        if(std::string(argv[i])=="-u") a=alphabet::url;
        if(std::string(argv[i])=="-d") m=mode::decode;
        if(std::string(argv[i])=="-n") add_newline=true;
    }

    while(std::cin) {
        std::cin.read(buffer.data(), buffer_size);
        std::string in(buffer.data(), std::cin.gcount());
        if(m==mode::encode) std::cout << base64_encode(in, a);
        else std::cout << base64_decode(in, a);
    }
    if(add_newline) std::cout << std::endl;
    return 0;
}
