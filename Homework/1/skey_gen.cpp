#include <vector>
#include <iostream>
#include <functional>
#include <string>
#include <iomanip>

void password_generation(std::string, int);

int main(int argc, char **argv){
    int iterations = 20;

    if(argc < 2 || argc > 3){
        std::cout << "Usage : " << argv[0] << " <secret_key> [iterations]" << std::endl;
        std::cout << "Default iterations is " << iterations << std::endl;
        return 1;
    }

    if(argc == 3){
        iterations = atoi(argv[2]);
        if(iterations < 1){
            std::cout << "Iterations must be at least 1" << std::endl;
            return 1;
        }
    }

    password_generation(std::string(argv[1]), iterations);

    return 0;
}

void password_generation(std::string str, int iterations){
    // Create hash functions using std hash templates
    std::vector<uint32_t> hashes(iterations);

    // make first hash the hashed input secret
    uint32_t cur_hash = std::hash<std::string>{}(str);

    for(auto &hash: hashes){
        hash = cur_hash;
        // builtin hash for integers appears to be the identity function
        // so make the number a string and hash the string
        cur_hash = std::hash<std::string>{}(std::to_string(cur_hash));
    }

    for(auto hash = hashes.rbegin(); hash != hashes.rend(); hash++){
            std::cout << "0x" << std::setfill('0') << std::setw(8)  << std::right << std::hex << *hash << std::endl;
    }
}
