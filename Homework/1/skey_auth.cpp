#include <fstream>
#include <string>
#include <iostream>
#include <stdio.h>

#define MAX_FILENAME 64

void store_hash(const char*, uint32_t);
void read_hash(const char*, uint32_t*);
bool authenticate(const char*, uint32_t);
int  get_user_file(const char*, char*, int);


int main(int argc, char **argv){
    uint32_t key;

    if(argc < 3 || argc > 4){
        std::cerr << "Usage: " << argv[0] << " <user> <key> [set]" << std::endl;
        std::cerr << "If set is 1 then the key supplied will be saved as the current hash for the user specified" << std::endl;
        return 1;
    }


    key = std::stoul(argv[2], nullptr, 0);
    if(argc == 4 && argv[3][0] == '1' && argv[3][1] == '\0'){

        char file[MAX_FILENAME];
        if(get_user_file(argv[1], &file[0], MAX_FILENAME)){
            return 1;
        }
        store_hash(file, key);
        return 0;
    }else{
        if(authenticate(argv[1], key)){
            std::cout << "Authenticated" << std::endl;
            return 0;
        }
        std::cout << "Invalid password" << std::endl;
        return 1;
    }

    return 1;
}

void store_hash(const char *file, uint32_t hash){
    std::ofstream f(file, std::ios::trunc);
    if(!f.is_open()){
        std::cerr << "Failed to open file" << std::endl;
        return;
    }
    f << std::hex << hash;
    f.close();
}

void read_hash(const char *file, uint32_t *hash){
    std::ifstream f(file);
    if(!f.is_open()){
        std::cerr << "Failed to open file, maybe it doesn't exist" << std::endl;
        *hash = 0;
        return;
    }
    f >> std::hex >> *hash;
    f.close();
}

bool authenticate(const char *user, uint32_t hash){
    uint32_t to_match;
    std::hash<std::string> str_hash;
    char file[MAX_FILENAME];

    if(get_user_file(user, &file[0], MAX_FILENAME)){
        //unable to create filename
        return false;
    }

    read_hash(file, &to_match);
    if(to_match == 0){
        return false;
    }

    if((uint32_t) str_hash(std::to_string(hash)) == to_match){
        store_hash(file, hash);
        return true;
    }

    return false;
}

int get_user_file(const char *user, char *buf, int size){
    int n = snprintf(buf, size, ".%s_hash", user);
    return !(n >= 0 && n < size);
}

