#include "Permuter.h"

Permuter::Permuter(int *perm, int bs):
    block_size(bs),
    permutation(perm, perm + block_size)
{

}

Permuter::~Permuter()
{

}

std::string Permuter::permute(std::string input)
{
    int i, j;

    if(i = input.size()%block_size){
        for(; i < block_size; i++){
            input += pad_character;
        }
    }

    std::string output = input;

    for(i = 0; i < input.size(); i+=block_size){
        for(j = 0; j < block_size; j++){
            output[i+j] = input[i + permutation[j]];
        }
    }
    return output;
}

std::string Permuter::unpermute(std::string input)
{
    std::string output = input;
    int i, j;
    for(i = 0; i < input.size(); i+=block_size){
        for(j = 0; j < block_size; j++){
            output[i + permutation[j]] = input[i+j];
        }
    }
    return output;
}
