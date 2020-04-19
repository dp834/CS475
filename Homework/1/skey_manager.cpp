#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>

#define HASH_LIST_PATH ".hashes_list"
#define CONFIRMATION (1 << 0)
#define REMAINING_WARNING (1 << 1)


int show_top_hash(const char*, uint8_t);
int store_hash_list(const char*);


int main(int argc, char **argv){

    if(argc < 1 || argc > 2){
        // Option to skip confimation of usage?
        std::cerr << "Usage: " << argv[0] <<" [store]" << std::endl;
        std::cerr << "Set store to 1 to store a hash list read from stdin" << std::endl;
        std::cerr << "If store is omitted then the next hash is printed" << std::endl;
    }

    if(argc == 2 && argv[1][0] == '1' && argv[1][1] == '\0'){
        return store_hash_list(HASH_LIST_PATH);
    }

    if(argc == 1){
        return show_top_hash(HASH_LIST_PATH, CONFIRMATION|REMAINING_WARNING);
    }

    return 0;
}

int store_hash_list(const char *fname){
    std::ofstream file(fname, std::ios::trunc);
    if(!file.is_open()){
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }

    for(std::string line; std::getline(std::cin,line);){
        file << line << std::endl;
    }

    file.close();
    return 0;
}

int show_top_hash(const char*fname, uint8_t flags){
    std::string fname_tmp = std::tmpnam(nullptr);
    std::ofstream ofile(fname_tmp);
    std::ifstream ifile(fname);
    std::string line;
    int i;

    if(!std::getline(ifile, line)){
        std::cerr << "ERROR: no hashes in file to read" << std::endl;
        return 1;
    }

    std::cout << line << std::endl;

    for(i = 0; std::getline(ifile, line); i++){
        ofile <<  line << std::endl;
    }

    ofile.close();
    ifile.close();

    if(flags & REMAINING_WARNING){
        std::cout << i << " hashes remaining" << std::endl;
    }

    if(flags & CONFIRMATION){
        char c;
        std::cout << "Discard hash from the list? (y/n):";
        while(c=getchar()){
            if(c == 'n' || c =='N'){
                if(remove(fname_tmp.c_str())){
                    std::cerr << "ERROR deleting temp file " << fname_tmp << std::endl;
                }
                return 1;
            }else if(c == 'y' || c =='Y'){
                break;
            }
            std::cout << "Discard hash from the list? (y/n):";
        }
    }

    if(rename(fname_tmp.c_str(), fname)){
        std::cerr << "ERROR moving temp file, hash list is not updated and contains used hash" << fname_tmp << std::endl;
        return 1;
    }

    return 0;
}
