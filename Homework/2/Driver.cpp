#include <iostream>
#include <fstream>
#include "Permuter.h"
#include "Wheel.h"


std::map<char, int> char_map = {
{'A', 0},  {'B', 1},  {'C', 2},  {'D', 3},  {'E', 4},  {'F', 5},  {'G', 6},  {'H', 7},  {'I', 8},  {'J', 9},  {'K', 10}, {'L', 11},
{'M', 12}, {'N', 13}, {'O', 14}, {'P', 15}, {'Q', 16}, {'R', 17}, {'S', 18}, {'T', 19}, {'U', 20}, {'V', 21}, {'W', 22}, {'X', 23},
{'Y', 24}, {'Z', 25}, {'0', 26}, {'1', 27}, {'2', 28}, {'3', 29}, {'4', 30}, {'5', 31}, {'6', 32}, {'7', 33}, {'8', 34}, {'9', 35}
};

std::map<int, char> reverse_char_map = {
{0, 'A'},  {1, 'B'},  {2, 'C'},  {3, 'D'},  {4, 'E'},  {5, 'F'},  {6, 'G'},  {7, 'H'},  {8, 'I'},  {9, 'J'},  {10, 'K'}, {11, 'L'},
{12, 'M'}, {13, 'N'}, {14, 'O'}, {15, 'P'}, {16, 'Q'}, {17, 'R'}, {18, 'S'}, {19, 'T'}, {20, 'U'}, {21, 'V'}, {22, 'W'}, {23, 'X'},
{24, 'Y'}, {25, 'Z'}, {26, '0'}, {27, '1'}, {28, '2'}, {29, '3'}, {30, '4'}, {31, '5'}, {32, '6'}, {33, '7'}, {34, '8'}, {35, '9'}
};

int usage(char *progname)
{
    std::cerr << "Usage: " << progname << " (e[ncrypt]|d[ecrypt]) <permutation> <window> [filename]" << std::endl;
    std::cerr << "permutation   - list of integers from 0-9 appearing once ie. 3145926870 or 0123456789" <<std::endl;
    std::cerr << "window        - list of 3 characters representing the inital offset of the left middle and right wheel respectively" <<std::endl;
    std::cerr << "filename      - will read text to encrypt/decrypt from file, if none is specified then use stdin" <<std::endl;
    std::cerr << "Note          - The message must contain all UPPERCASE letters" <<std::endl;
    return -1;
}

int encode(int permutation[10], char windows[3], std::istream *input){
    Permuter p(permutation, 10);

    std::string wiring_left = "2YZ01AWIPKSN3TERMUC5V6X7FQOL48GD9BJH";
    Wheel left(wiring_left, 5, windows[0], char_map, reverse_char_map);

    std::string wiring_middle = "0LX128HB3NROKDT7C6PIVJ4AUWME95QSZGYF";
    Wheel middle(wiring_middle, 7, windows[1], char_map, reverse_char_map);

    std::string wiring_right = "35HEFGDQ8M2KLJNSUWOVRXZCI9T7BPA01Y64";
    Wheel right(wiring_right, 1, windows[2], char_map, reverse_char_map);

    std::string line;
    while(*input){
        std::getline(*input, line);
        std::cout <<  left.encode(middle.encode(right.encode(p.permute(line))));
    }
    std::cout << std::endl;
    return 0;
}

int decode(int permutation[10], char windows[3], std::istream *input){
    Permuter p(permutation, 10);

    std::string wiring_left = "2YZ01AWIPKSN3TERMUC5V6X7FQOL48GD9BJH";
    Wheel left(wiring_left, 5, windows[0], char_map, reverse_char_map);

    std::string wiring_middle = "0LX128HB3NROKDT7C6PIVJ4AUWME95QSZGYF";
    Wheel middle(wiring_middle, 7, windows[1], char_map, reverse_char_map);

    std::string wiring_right = "35HEFGDQ8M2KLJNSUWOVRXZCI9T7BPA01Y64";
    Wheel right(wiring_right, 1, windows[2], char_map, reverse_char_map);

    std::string line;
    while(*input){
        std::getline(*input, line);
        std::cout << p.unpermute(right.decode(middle.decode(left.decode(line))));
    }
    std::cout << std::endl;

    return 0;
}

int main(int argc, char *argv[])
{
    int  permutation[10];
    bool perm_check[10] = {false};
    char windows[3], c;
    bool encrypt = true;
    int i;
    std::ifstream file;
    std::istream *input;

    if(argc != 4 && argc != 5){
        return usage(argv[0]);
    }

    if(argv[1][0] == 'e'){
        encrypt = true;
    }else if(argv[1][0] == 'd'){
        encrypt = false;
    }else{
        return usage(argv[0]);
    }

    for(i = 0; i < 10 ; i++){
        c = argv[2][i];
        /* if we reach the end of the string
         * or we are not a digit then fail and print usage */
        if((c == '\0') || (c - '0' < 0) || c - '9' > 0){
            return usage(argv[0]);
        }
        /* c is now a valid char */


        /* if index is being reused then fail */
        if(perm_check[c-'0']){
            return usage(argv[0]);
        }

        perm_check[c-'0'] = true;
        permutation[i] = c - '0';
    }

    /* Permutation is too long*/
    if(argv[2][i] != '\0'){
        return usage(argv[0]);
    }

    for(i = 0; i < 3; i++){
        c = argv[3][i];

        /* not enough window characters*/
        if(c == '\0'){
            return usage(argv[0]);
        }

        /* Check that it's a valid character and
         * convert lowercase to uppercase */

        if((c - '0' >= 0) && (c - '9' <= 0)){
            /* char is a number all good */
        }else if((c - 'a' >= 0) && (c - 'z' <= 0)){
            /* char is a lowercase letter convert to upper */
            c = c - ('a' - 'A');
        }else if((c - 'A' >= 0) && (c - 'Z' <= 0)){
            /* char is uppercase all good */
        }else{
            /* char is not in the character map of valid characters */
            return usage(argv[0]);
        }
        windows[i] = c;
    }


    /* windows is too long*/
    if(argv[3][i] != '\0'){
        return usage(argv[0]);
    }

    /* use stdin as file */
    if(argc != 5){
        input = &std::cin;
    }else{
        /* open file */
        file.open(argv[4], std::ifstream::in);
        if(!file.good()){
            std::cerr << "Failed to open file " << argv[4] << std::endl;
            return -1;
        }
        input = &file;
    }

    if(encrypt){
        return encode(permutation, windows, input);
    }
    return decode(permutation, windows, input);
}

