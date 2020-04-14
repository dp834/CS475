#include <iostream>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <unistd.h>

extern char *optarg;
extern int optind, opterr, optopt;


#define HASH_FILE_PATH ".homework1_hash"

uint32_t hash_function(uint32_t);
void password_generation(int);
void store_hash(uint32_t);
void read_hash(uint32_t*);
bool authenticate(uint32_t);

void usage(char *progname){
    std::cout << "Usage: " << progname << " -g[count]" << std::endl;
    std::cout << "       " << progname << " -a password" << std::endl;
}

int main(int argc, char **argv){
    int opt = 0;
    int count = 10;
    uint32_t password;

    while((opt = getopt(argc, argv, "g::a:h")) != -1){
        switch(opt){
            /* Generate new list
             * optional argument of how many to generate, default 10 */
            case'g':
                /* initialize random seed */
                std::srand(std::time(nullptr));
                if(optarg){
                    count = std::stoi(optarg);
                }
                password_generation(count);
                return 0;
            /* Authenticate
             * must take a int as input to authenticate against */
            case'a':
                password = std::stoul(optarg, nullptr, 0);
                if(authenticate(password)){
                    std::cout << "Authenticated" << std::endl;
                }else{
                    std::cout << "Invalid password" << std::endl;
                }
                return 0;
            /* Help, fallthrough*/
            case'h':
            default:
                usage(argv[0]);
                break;
        }

    }

    if(argc == 1){
        usage(argv[0]);
    }

    return 0;
}

void password_generation(int n){
    std::vector<uint32_t> hashes(n);
    uint32_t secret_key = std::rand();

    for(auto& hash: hashes){
        hash = hash_function(secret_key);
        secret_key = hash;
    }

    for(auto hash = hashes.rbegin(); hash != hashes.rend(); hash++){
            std::cout << "0x" << std::hex << *hash << std::endl;
    }

    store_hash(hashes.back());
}

void store_hash(uint32_t hash){
    std::ofstream file;
    file.open(HASH_FILE_PATH, std::ios::trunc);
    if(!file.is_open()){
        std::cout << "Failed to open file" << std::endl;
        return;
    }
    file << std::hex << hash;
    file.close();
}

void read_hash(uint32_t *hash){
    std::ifstream file;
    file.open(HASH_FILE_PATH);
    if(!file.is_open()){
        std::cout << "Failed to open file, maybe it doesn't exist" << std::endl;
        *hash = 0;
        return;
    }
    file >> std::hex >> *hash;
    file.close();
}

uint32_t hash_function(uint32_t in){
    return ~(in<<1);
}

bool authenticate(uint32_t hash){
    uint32_t to_match;
    read_hash(&to_match);

    if(to_match == 0){
        return false;
    }

    if(hash_function(hash) == to_match){
        store_hash(hash);
        return true;
    }

    return false;
}
