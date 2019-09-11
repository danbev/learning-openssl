#include <iostream>
#include <vector>
#include <algorithm>
#include <iterator>
#include <random>
  
using namespace std;
int main() {
  std::random_device rd;  //Will be used to obtain a seed for the random number engine
  std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
  uint8_t reset_token[10];
  std::generate(std::begin(reset_token), std::end(reset_token), gen);
  for (int i = 0; i < 10; i++) {
    cout << reset_token[i] << '\n';
  }
  return 0;
}
