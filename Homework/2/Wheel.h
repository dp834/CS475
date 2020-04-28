#include <vector>
#include <map>
#include <string>

class Wheel
{
private:
    int rotate_period;
    int rotate_counter = 0;
    int wheel_length;
    std::vector<int> wiring;
    int current_offset;
    std::map<char, int> char_map;
    std::map<int, char> reverse_char_map;


public:
    Wheel(std::string &mapping, int rotate_period, char initial_view, std::map<char,int> &map, std::map<int, char> &reverse_map);
    char encode(char c);
    char decode(char c);
    std::string encode(std::string str);
    std::string decode(std::string str);
};
