#include <iostream>
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

void permute_test(){
    int permutation[] = {3,1,4,5,9,2,6,8,7,0};
    Permuter p(permutation, 10);
    std::string str = "01234567890123456789";
    std::string out = p.permute(str);
    std::cout << p.unpermute(out) << std::endl;
}

void wheel_test(){
    std::string wiring = "2YZ01AWIPKSN3TERMUC5V6X7FQOL48GD9BJH";
    Wheel e(wiring, 4, 'W', char_map, reverse_char_map);
    std::string msg = "THISISMYTESTMESSAGE";
    std::string encoded = e.encode(msg);
    Wheel d(wiring, 4, 'W', char_map, reverse_char_map);
    std::string decoded = d.decode(encoded);
    std::cout << msg << std::endl;
    std::cout << encoded << std::endl;
    std::cout << decoded << std::endl;
}

void full_test()
{
    int permutation[] = {3,1,4,5,9,2,6,8,7,0};
    Permuter p(permutation, 10);

    std::string wiring_left = "2YZ01AWIPKSN3TERMUC5V6X7FQOL48GD9BJH";
    Wheel left(wiring_left, 5, '2', char_map, reverse_char_map);

    std::string wiring_middle = "0LX128HB3NROKDT7C6PIVJ4AUWME95QSZGYF";
    Wheel middle(wiring_middle, 7, '0', char_map, reverse_char_map);

    std::string wiring_right = "35HEFGDQ8M2KLJNSUWOVRXZCI9T7BPA01Y64";
    Wheel right(wiring_right, 1, '3', char_map, reverse_char_map);

    Wheel dleft(wiring_left, 5, '2', char_map, reverse_char_map);
    Wheel dmiddle(wiring_middle, 7, '0', char_map, reverse_char_map);
    Wheel dright(wiring_right, 1, '3', char_map, reverse_char_map);

    std::string msg = "THIS IS MY TEST MESSAGE";
    std::string encoded = left.encode(middle.encode(right.encode(p.permute(msg))));
    std::string decoded = p.unpermute(dright.decode(dmiddle.decode(dleft.decode(encoded))));
    
    std::cout << msg << std::endl;
    std::cout << encoded << std::endl;
    std::cout << decoded << std::endl;
}

int main(int argc, char *argv[])
{

    full_test();
    permute_test();
    wheel_test();
    return 0;
}



