#include "Wheel.h"
#include <bits/stdc++.h> 

/* mapping and map should have the same size */
Wheel::Wheel(std::string &mapping, int period, char initial_view, std::map<char,int> &map, std::map<int,char> &reverse_map) :
   rotate_period(period),
   char_map(map),
   reverse_char_map(reverse_map),
   wheel_length(mapping.size())
{
    for(auto c: mapping){
        wiring.push_back(char_map[c]);
    }

    current_offset = find(wiring.begin(), wiring.end(), char_map[initial_view]) - wiring.begin();

}


char Wheel::encode(char c)
{
    /* If character is not in map don't encode it */
    if(char_map.find(c) == char_map.end()){
        return c;
    }
    if(++rotate_counter == rotate_period){
        current_offset = (current_offset + 1) % wheel_length;
        rotate_counter = 0;
    }
    int index = (char_map[c] + current_offset) % wheel_length;
    index = (wiring[index] - current_offset + wheel_length) % wheel_length;
    return reverse_char_map[index];
}

char Wheel::decode(char c)
{
    /* If character is not in map don't encode it */
    if(char_map.find(c) == char_map.end()){
        return c;
    }
    if(++rotate_counter == rotate_period){
        current_offset = (current_offset + 1) % wheel_length;
        rotate_counter = 0;
    }
    int index = find(wiring.begin(), wiring.end(), (char_map[c] + current_offset) % wheel_length) - wiring.begin();
    // Make sure we are in range, and modulus of negative is not well defined in c++
    index = (index - current_offset + wheel_length) % wheel_length;
    return reverse_char_map[index % wheel_length];
}

std::string Wheel::encode(std::string str)
{
    std::string out = "";
    for(auto c: str){
        out += encode(c);
    }
    return out;
}
std::string Wheel::decode(std::string str)
{
    std::string out = "";
    for(auto c: str){
        out += decode(c);
    }
    return out;
}
