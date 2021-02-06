#include <string.h>
//#include <stdio.h>

int main(int argc, char** argv) {
  char array[10];
  //printf("argv[1]: %s\n", argv[1]); 

  strcpy(array, argv[1]);

  //printf("array: %s\n", array); 
  return 0;
};
