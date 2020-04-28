#include <vector>
#include <string>

class Permuter{

private:
    Permuter();
    int block_size;
    std::vector<int> permutation;
    char pad_character = 'X';


public:
    Permuter(int *permutation, int bs);
    std::string permute(std::string input);
    std::string unpermute(std::string input);
    ~Permuter();
};
