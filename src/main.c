#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "tar.h"
#include "fuzzer.h"

int main(int argc, char *argv[])
{
  if (argc <= 1)
  {
    printf("You have to write the name of the file of the extratctor after the fuzzer executable. Like this:\n");
    printf("./fuzzer ./<path-to-extractor>");
    return -1;
  }
  printf("\n--- Starting the following generation-based fuzzer ---\n");
  printf("%s\n", argv[1]);

  FILE *fuzzer_test = fopen(argv[1], "rb");
  if (!fuzzer_test)
  {
    printf("The extractor \"%s\" doesn't exist\n", argv[1]);
    return -1;
  }
  fclose(fuzzer_test);

  srand(time(NULL));

  fuzz(argv[1]);

  return 0;
}