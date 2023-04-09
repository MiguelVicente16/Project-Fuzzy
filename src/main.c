#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "tar.h"
#include "fuzzer.h"
#include "test.h"

/**
 * The main function of the generation-based fuzzer.
 * It checks the command line arguments, verifies that the extractor file exists, and then calls the fuzz function.
 * @param[in] argc The number of command line arguments.
 * @param[in] argv An array of strings containing the command line arguments.
 * @param[out] 0 if the fuzzer ran successfully, -1 otherwise.
**/
int main(int argc, char *argv[])
{
  // Check if the correct number of arguments was provided
  if (argc < 2)
  {
    printf("You have to write the name of the file of the extractor after the fuzzer executable. Like this:\n");
    printf("./fuzzer ./<path-to-extractor>");
    return -1;
  }

  printf("\n--- Starting the following generation-based fuzzer ---\n");
  printf("%s\n", argv[1]);

  // Check if the extractor file exists
  FILE *fuzzer_test = fopen(argv[1], "rb");
  if (!fuzzer_test)
  {
  printf("The extractor \"%s\" doesn't exist\n", argv[1]);
  return -1;
  }
  fclose(fuzzer_test);

  // Seed the random number generator
  srand(time(NULL));

  // Call the fuzz function with the provided extractor file
  fuzz(argv[1]);

  return 0;
}