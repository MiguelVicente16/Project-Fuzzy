#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "fuzzer.h"
#include "tar.h"

static tar_t header;
static const char WEIRD_CHARS[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 127, 128, 130, 200, 255}; // pensar se colocamos mais

static const unsigned POSSIBLE_MODES[] = {
    TSUID,
    TSGID,
    TSVTX,
    TUREAD,
    TUWRITE,
    TUEXEC,
    TGREAD,
    TGWRITE,
    TGEXEC,
    TOREAD,
    TOWRITE,
    TOEXEC
};

static const unsigned TYPE_FLAG_VALUES[] = {
    REGTYPE,        
    AREGTYPE,         
    LNKTYPE,            
    SYMTYPE,            
    CHRTYPE,            
    BLKTYPE,  
    DIRTYPE,  
    FIFOTYPE, 
    CONTTYPE,
    XHDTYPE, 
    XGLTYPE, 
};


/**
  * This function tests the extractor with the file TEST_FILE and records some stats.
  * 
  * @param[in] fuzzer A pointer to the Fuzzer struct containing the fuzzer's state and statistics.
  * @param[out] int The function returns an integer indicating the outcome of the test.
  *             Returns 0: If the extractor ran without any errors, but the output did not contain the crash message.
  *             Returns 1: If the extractor ran without any errors and the output contained the crash message.
  *             Returns -1: If there was an error running the extractor or if the command to close the file pipe failed.
  * 
*/
int test_file_extractor(Fuzzer* fuzzer)
{
  // Return value
  int rv = 0; 
  // Command buffer
  char cmd[250]; 
  
  // Create command to execute the extractor with the TEST_FILE as input
  sprintf(cmd, "%s %s 2>&1", fuzzer->extractor_file, TEST_FILE);
  printf("yeah");
  char buf[LEN_CRASH_MSG];
  FILE *fp;

  // Open a pipe to execute the extractor command
  if ((fp = popen(cmd, "r")) == NULL)
  {
    puts("Error opening pipe!");
    return -1;
  }

  // Read the output of the extractor command
  if (fgets(buf, LEN_CRASH_MSG, fp) == NULL)
    fuzzer->no_out_number++;  // No output from extractor
  else if (strncmp(buf, CRASH_MSG, LEN_CRASH_MSG) != 0)
    fuzzer->errors_number++;  // Extractor returned an error message
  else
  {
    // Extractor identified a crash
    rv = 1;
    fuzzer->crashes_number++;

    // Rename the input file with a new name indicating the test and crash number
    char new_name[100];
    sprintf(new_name, "success_%03u_%s.tar", fuzzer->crashes_number, fuzzer->current_test);
    printf(KGRN "Crash message n°%u " KNRM "-> %s \n", fuzzer->crashes_number, fuzzer->current_test);
    rename(TEST_FILE, new_name);
  }
  
  // Close the pipe and check if there was an error
  if (pclose(fp) == -1)
  {
    puts("Command not found");
    rv = -1;
  }
  
  // Return the outcome of the test
  return rv;
}

/** 
 * This function tests the header of an empty tar archive by creating an empty tar file 
 *  with the given header and passing it to the extractor. 
 * 
* @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
**/
void test_header(Fuzzer *fuzzer)
{
  write_empty_tar(TEST_FILE, &header); // Create an empty tar file with the given header // Podemos sq meter o TEST_FILE na struct
  test_file_extractor(fuzzer); // Pass the file to the extractor for testing
}

/** 
  * This function sets the current test name being run in the Fuzzer struct. 
  * 
  * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
  * @param[in] name the test name (a string) 
  * @param[in] field_name the field name (also a string).
  **/
void set_name(Fuzzer* fuzzer, const char *name, const char *field_name)
{
  // Use sprintf to format the current test name and save it in the Fuzzer struct
  sprintf(fuzzer->current_test, "%s_%s", field_name, name);
}

/**
 * This function applies a set of tests to the field, such as testing for an empty field, 
 * a non-numeric field, a field with all the same character, and so on. Each test is 
 * performed by setting the field buffer to a specific value and then calling a test_header function, 
 * which generates an informative test name and runs the test using the Fuzzer objectm and 
 * then checking how the program behaves in response.
 * 
 * Note that this function does not return anything; it is only responsible for performing tests
 * on the field and logging the results.
 * 
 * By calling this function with different field names and sizes, you can quickly generate a wide 
 * variety of tests for different fields in your codebase.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * @param[in] field_name: A null-terminated string representing the name of the field being tested. This is used for generating informative test names.
 * @param[in] field: A pointer to the buffer containing the field being tested.
 * @param[in] size: The size of the field buffer.
 * 
**/
void generic_field_tests(Fuzzer* fuzzer, const char *field_name, char *field, unsigned size)
{
  // Test case: empty field
  set_name(fuzzer, "empty", field_name);
  strncpy(field, "", size);
  test_header(fuzzer);

  // Test case: non-numeric field
  set_name(fuzzer, "not_numeric", field_name);
  strncpy(field, "hello", size);
  test_header(fuzzer);

  // Test case: field filled with the maximum digit '7'
  set_name(fuzzer, "big", field_name);
  memset(field, '7', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);

  // Test case: field filled with non-octal digit '9'
  set_name(fuzzer, "not_octal", field_name);
  memset(field, '9', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);

  // Test case: field not terminated with a null character
  set_name(fuzzer, "not_terminated", field_name);
  memset(field, '4', size);
  test_header(fuzzer);

  // Test case: field with a null character in the middle, but not at the end
  set_name(fuzzer, "middle_null_termination", field_name);
  memset(field, 0, size);
  memset(field, '2', size / 2);
  test_header(fuzzer);

  // Test case: field with a null character in the middle and at the end
  set_name(fuzzer, "0 and_middle_null_termination", field_name);
  memset(field, 0, size);
  memset(field, '0', size / 2);
  test_header(fuzzer);

  // Test case: field containing non-ASCII character
  set_name(fuzzer, "not_ascii", field_name);
  strncpy(field, "😂", size);
  test_header(fuzzer);

  // Test case: field filled with '0' character
  set_name(fuzzer, "all_0", field_name);
  memset(field, '0', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);

  // Test case: field with all null characters except for the last one, which is '0'
  set_name(fuzzer, "all_null_but_end_0", field_name);
  memset(field, 0, size - 1);
  field[size - 1] = '0';
  test_header(fuzzer);
}

/**
  * This function tests the "name" and "linkname" fields of the tar header by calling
  * various tests on them, including empty values, weird characters, forbidden characters,
  * non-null terminated strings, strings of zeros, non-ASCII characters (emojis), and directories.
  * 
  *@param[in]linkname: A boolean indicating whether to test the "linkname" or "name" field.
  *@param[in]fuzzer: A pointer to the Fuzzer struct containing the test case and options.
  * 
**/
void test_names(int linkname, Fuzzer *fuzzer) //Aqui verificar se não dá para otimizar, escrever em menos linhas
{
      // Set the tar header with default values
      set_header(&header);

      // Get the appropriate field to test (linkname or name)
      char *field = header.linkname;
      char field_name[] = "linkname";
      unsigned size = LINKNAME_LEN;

      if (!linkname)
      {
        field = header.name;
        sprintf(field_name, "name");
        size = NAME_LEN;
      }
      else
      {
        // Test the linkname with the same value as the name
        set_name(fuzzer, "same_as_name", field_name);
        strncpy(field, header.name, size);
        test_header(fuzzer);
      }

      // Test an empty field
      set_name(fuzzer, "empty", field_name);
      strncpy(field, "", size);
      test_header(fuzzer);

      // Test the field with weird characters
      strncpy(field, "0" EXT, size);
      for (unsigned i = 0; i < sizeof(WEIRD_CHARS); i++)
      {
        field[0] = WEIRD_CHARS[i];
        sprintf(fuzzer->current_test, "%s_weird_char='%c'", field_name, field[0]);
        test_header(fuzzer);
      }

      // Test the field with forbidden characters
      char forbidden_char[] = {'*', '\\', '/', '"', '?', ' '};
      for (unsigned i = 0; i < sizeof(forbidden_char); i++)
      {
        field[0] = forbidden_char[i];
        sprintf(fuzzer->current_test, "%s_weird_char='%c'", field_name, field[0]);
        test_header(fuzzer);
      }

      // Test the field with a string that's not null-terminated
      set_name(fuzzer, "not_terminated", field_name);
      memset(field, 'a', size);
      test_header(fuzzer);

      // Test the field with a string of zeros
      set_name(fuzzer, "fill_all", field_name);
      sprintf(field, "%0*d" EXT, (int)(size - strlen(EXT) - 1), 0);
      test_header(fuzzer);

      // Test the field with non-ASCII characters (in this case, emojis)
      set_name(fuzzer, "non_ascii", field_name);
      strncpy(field, "😂 😎" EXT, size);
      test_header(fuzzer);

      // Test the field as a directory
      set_name(fuzzer, "directory", field_name);
      strncpy(field, "tests" EXT "/", size);
      test_header(fuzzer);
}

/**
 * This function tests the "mode" field of the header by calling
 * the generic_field_tests function with the appropriate arguments, 
 * then test all possible values of the mode field.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 **/
void test_mode(Fuzzer *fuzzer)
{
  // Initialize the header and the field for the mode
  set_header(&header);
  char *field = header.mode;

  // Run generic tests on the mode field
  generic_field_tests(fuzzer, "mode", field, MODE_LEN);

  // Test all possible values of the mode field
  for (unsigned i = 0; i < sizeof(POSSIBLE_MODES) / sizeof(POSSIBLE_MODES[0]); i++)
  {
    // Initialize the header and format the current mode value into the field
    set_header(&header);
    sprintf(field, "%07o", POSSIBLE_MODES[i]);

    // Set the current test name to reflect the current mode value
    sprintf(fuzzer->current_test, "mode='%s'", field);

    // Run the header test with the current mode value
    test_header(fuzzer);
  }
}

/**
 * This function tests the "uid" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 **/
void test_uid(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the uid
  set_header(&header);
  char *field = header.uid;

  // Run generic tests on the uid field
  generic_field_tests(fuzzer, "uid", field, UID_LEN);
}

/**
 * This function tests the "gid" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 **/
void test_gid(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the gid
  set_header(&header);
  char *field = header.gid;

  // Run generic tests on the gid field
  generic_field_tests(fuzzer, "gid", field, GID_LEN);
}

/**
 * 
 * This function tests the "size" field of the header by calling
 * the generic_field_tests function with the appropriate arguments, and then
 * runs a series of tests on various edge cases for the field.
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
**/
void test_size(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the size
  set_header(&header);
  char *field = header.size;

  // Run generic tests on the size field
  generic_field_tests(fuzzer, "size", field, SIZE_LEN);

  // Test various edge cases for the size field
  // First, test a file with a size of 0 bytes
  char buffer[] = "hello";
  unsigned long len_buffer = strlen(buffer);
  set_name(fuzzer, "0", "size");
  set_size_header(&header, 0);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);

  // Next, test a file with a size smaller than the actual size of the data
  set_name(fuzzer, "too_small", "size");
  set_size_header(&header, 2);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);

  // Then, test a file with a size larger than the actual size of the data
  set_name(fuzzer, "too_big", "size");
  set_size_header(&header, 20);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);

  // Test a file with a size that exceeds the maximum allowed value
  set_name(fuzzer, "far_too_big", "size");
  set_size_header(&header, END_LEN * 2);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);

  // Test a file with a size that exceeds the maximum allowed value and has a long filename
  set_name(fuzzer, "far_far_too_big", "size");
  set_size_header(&header, END_LEN * 2);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);

  // Test a file with a negative size
  set_name(fuzzer, "negative", "size");
  sprintf(field, "%011o", -2);
  write_tar(TEST_FILE, &header, buffer, len_buffer);
  test_file_extractor(fuzzer);
}

/**
 * This function tests the "mtime" field of the header by calling
 * the generic_field_tests function with the appropriate arguments, 
 * and then tests it with several specific values.
 * 
 *@param[in]fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 **/
void test_mtime(Fuzzer* fuzzer)
{
  // Set the tar header with default values
  set_header(&header);

  // Get the appropriate field to test (mtime)
  char *field = header.mtime;
  char field_name[] = "mtime";

  // Call the generic_field_tests function to test the field with default values
  generic_field_tests(fuzzer, field_name, field, MTIME_LEN);

  // Test the field with the current time
  set_name(fuzzer, "current", field_name);
  sprintf(field, "%lo", (unsigned long)time(NULL));
  test_header(fuzzer);

  // Test the field with a time 50 hours in the future
  set_name(fuzzer, "later", field_name);
  sprintf(field, "%lo", (unsigned long)time(NULL) + 50 * 3600);
  test_header(fuzzer);

  // Test the field with a time 50 hours in the past
  set_name(fuzzer, "sooner", field_name);
  sprintf(field, "%lo", (unsigned long)time(NULL) - 50 * 3600);
  test_header(fuzzer);

  // Test the field with a time far in the future
  set_name(fuzzer, "far_future", field_name);
  sprintf(field, "%lo", (unsigned long)time(NULL) * 2);
  test_header(fuzzer);
}

/**
 * This function tests the "chksum" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 **/
void test_chksum(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the chksum
  set_header(&header);
  char *field = header.chksum;

  // Run generic tests on the gid field
  generic_field_tests(fuzzer, "chksum", field, CHKSUM_LEN);
}

/**
  * This function tests the `typeflag` field of the header struct
  * by assigning it all possible values (0x00 to 0xFF) and testing the resulting header with each value.
  * 
  *@param[in]fuzzer a pointer to a Fuzzer object to be used for testing.
  **/
void test_typeflag(Fuzzer* fuzzer)
{
  // Initialize header struct to initial values
  set_header(&header);

  // Name of the field being tested
  char field_name[] = "typeflag";

  // String to hold the current test name
  char name_current_test[30];

  // Loop through each possible value for the typeflag field
  for (unsigned i = 0; i < sizeof(TYPE_FLAG_VALUES)/sizeof(TYPE_FLAG_VALUES[0]); i++)
  {
      // Set the name of the current test to indicate the value of typeflag
      sprintf(name_current_test, "value=%c", TYPE_FLAG_VALUES[i]);

      // Set the typeflag field of the header struct to the current value of i
      header.typeflag = TYPE_FLAG_VALUES[i];

      // Set the name of the current test case to the value of typeflag
      set_name(fuzzer, name_current_test, field_name);

      // Test the header with the updated typeflag value
      test_header(fuzzer);
  }

 /* 
 // Iterate over all possible values of `typeflag`
  for (unsigned i = 0; i < 0x100; i++)
  {
    // Set the name of the current test to indicate the value of `typeflag`
    sprintf(name_current_test, "value=0x%02x", i);

    // Set the `typeflag` field of the header struct to the current value of `i`
    header.typeflag = (char)i;

    // Set the name of the current test case to the value of `typeflag`
    set_name(fuzzer, name_current_test, field_name);

    // Test the header with the updated `typeflag` value
    test_header(fuzzer);
  }
  */

//generic_field_tests(fuzzer, "mode", field, MODE_LEN);
}

/**
 * This function tests the "linkname" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 **/
void test_linkname(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the linkname
  set_header(&header);
  char *field = header.linkname;

  // Run generic tests on the linkname field
  generic_field_tests(fuzzer, "linkname", field, LINKNAME_LEN);

  // Test the linkname field for valid names
  // This function tests the linkname for invalid characters and empty names
  test_names(1, fuzzer);
}

/**
 * This function tests the "magic" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 **/
void test_magic(Fuzzer* fuzzer)
{
  // Initialize the header and the field for the magic field
  set_header(&header);
  char *field = header.magic;

  // Run generic tests on the magic field
  generic_field_tests(fuzzer, "magic", field, MAGIC_LEN);
}

/**
 * This function tests the "version" field of the header by calling
 * the generic_field_tests function with the appropriate arguments, 
 * then test all possible values for the digits of the version field.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 **/
void test_version(Fuzzer* fuzzer)
{
  // Set up the header and field for the version test
  set_header(&header);
  char *field = header.version;
  
  // Run generic tests on the version field
  generic_field_tests(fuzzer, "version", field, VERSION_LEN);

  // Loop over all possible values for the version field (64 total)
  for (unsigned i = 0; i < 64; i++)
  {
    // Set the version field to the current value of i
    field[1] = i % 8 + '0';  // octal digit represented by the lower 3 bits
    field[0] = i / 8 + '0';  // octal digit represented by the upper 3 bits
    
    // Format the current test case name using the current value of the version field
    sprintf(fuzzer->current_test, "version=\'%c%c\'", field[0], field[1]);
    
    // Run the header test with the current version field value
    test_header(fuzzer);
  }
}

/**
 * This function tests the "uname/gname" field of the header by calling
 * the generic_field_tests function with the appropriate arguments.
 * @param[in] gname  If is set to 0, the function tests the uname field.
 *                   If is set to 1, the function tests the gname field.
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 **/
void test_uname(Fuzzer* fuzzer, int gname)
{
  char *field = header.uname;  // Set the field pointer to the uname field
  char field_name[] = "uname";  // Set the field name to "uname" by default
  unsigned size = UNAME_LEN;  // Set the field size to the length of the uname field

  if (!gname)  // If gname is 0, test the uname field
  {
    field = header.gname;  // Set the field pointer to the gname field
    sprintf(field_name, "gname");  // Change the field name to "gname"
    size = GNAME_LEN;  // Set the field size to the length of the gname field
  }
  
  set_header(&header);  // Initialize the header
  generic_field_tests(fuzzer, field_name, field, size);  // Run generic tests on the field
}

/**
 * This function tests the behavior of the tar archive end-of-file (EOF) bytes.
 * It sets up a tar header and writes it to a test file along with a buffer of
 * data. Then it writes the specified number of EOF bytes to the end of the
 * file and tests the extractor's behavior with and without a file.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options.
 * 
 */
void test_end_bytes(Fuzzer* fuzzer)
{
  char end_bytes[END_LEN * 2]; // buffer to hold the end-of-file bytes
  memset(end_bytes, 0, END_LEN * 2); // initialize buffer to all zeroes

  char buffer[] = "hello"; // data buffer to write to the test file
  size_t len_buffer = strlen(buffer); // length of data buffer

  set_header(&header); // initialize tar header
  set_size_header(&header, strlen(buffer)); // set the size of the data in the header

  int lengths[] = {END_LEN * 2, END_LEN, 512, 1, 0}; // array of different EOF byte lengths to test

  // iterate through the different EOF byte lengths to test
  for (unsigned i = 0; i < sizeof(lengths) / sizeof(int); i++)
  {
    // test with a file containing data
    sprintf(fuzzer->current_test, "end_bytes(%d)_with_file", lengths[i]);
    write_tar_end(TEST_FILE, &header, buffer, len_buffer, end_bytes, lengths[i]);
    test_file_extractor(fuzzer);

    // test without a file (empty file)
    sprintf(fuzzer->current_test, "end_bytes(%d)_w-o_file", lengths[i]);
    write_tar_end(TEST_FILE, &header, "", 0, end_bytes, lengths[i]);
    test_file_extractor(fuzzer);
  }
}

/**
 * This function generates various tar archive files with different types of entries, 
 * including regular files, directories, and an empty archive. It also creates a 
 * large file entry to test the handling of large files. After creating each archive, 
 * the function tests the file extractor with the generated archive to ensure 
 * that the extraction is successful.
 * 
 * @param[in] fuzzer: A pointer to the Fuzzer struct containing the test case and options. 
 * 
**/
void test_files(Fuzzer* fuzzer)
{
  const size_t N = 50;
  tar_entry files[N]; // declare an array of 50 tar_entry structs
  tar_entry *entries = &files[0]; // create a pointer to the first element of the array

  // initialize each element of the array
  for (size_t i = 0; i < N; i++)
  {
    set_header(&files[i].header); // set the header of the i-th file
    files[i].content = NULL; // initialize the content of the i-th file to NULL
    files[i].size = 0; // set the size of the i-th file to zero
  }

  // Create and write N files to the tar archive
  sprintf(fuzzer->current_test, "%lu_files", N); // set the current test name

  for (size_t i = 0; i < N; i++)
  {
    sprintf(files[i].header.name, "this_is_the_file_number_%lu" EXT, i); // set the name of the i-th file
    files[i].content = malloc(30); // allocate memory for the content of the i-th file
    sprintf(files[i].content, "file number %lu", i); // set the content to a string with the i-th file number
    files[i].size = strlen(files[i].content); // set the size of the i-th file
  }

  write_tar_entries(TEST_FILE, files, N); // write the tar archive to disk
  test_file_extractor(fuzzer); // test the file extractor with the generated tar archive

  // create a tar archive with 5 files having the same name
  set_name(fuzzer, "same_name", "files"); // set the name of the current test
  for (unsigned i = 0; i < 5; i++)
  {
    strncpy(files[i].header.name, "same_name" EXT, NAME_LEN); // set the name of the i-th file
    files[i].content = malloc(50); // allocate memory for the content of the i-th file
    sprintf(files[i].content, "file number %d", i); // set the content of the i-th file
    files[i].size = strlen(files[i].content); // set the size of the i-th file
  }
  write_tar_entries(TEST_FILE, files, 5); // write the tar archive to disk
  test_file_extractor(fuzzer); // test the file extractor with the generated tar archive

  // create a tar archive with a directory-like file
  set_name(fuzzer, "dir_with_data", "files"); // set the name of the current test

  strncpy(entries->header.name, "test" EXT "/", NAME_LEN); // set the name of the directory-like file
  entries->content = malloc(50); // allocate memory for the content of the directory-like file
  entries->size = sprintf(entries->content, "content of the directory like if it was a file"); // set the content and size of the directory-like file
  
  write_tar_entries(TEST_FILE, files, 1); // write the tar archive to disk
  test_file_extractor(fuzzer); // test the file extractor with the generated tar archive

  // create an empty tar archive and test it
  FILE *f = fopen(TEST_FILE, "wb"); // create an empty file
  if (f)
  {
    fclose(f); // close the file
    set_name(fuzzer, "empty_tar", "files"); // set the name of the current test
    test_file_extractor(fuzzer); // test the file extractor with the generated tar archive
  }
  
  // Create and write a large file to the tar archive
  set_name(fuzzer, "big_file", "files");
  set_header(&entries->header); // Set the header of the entry to default values

  size_t big = 50 * 1000 * 1000; // Size of the large file in bytes

  entries->content = malloc(big); // Allocate memory for the content of the tar entry entries to store the large file.
  memset(entries->content, 'A', big); // Fill the allocated memory with the character 'A'. This is done to ensure that the file content is completely written to the allocated memory.
  entries->size = big; // Set the size of the tar entry to the size of the large file in bytes.
  
  write_tar_entries(TEST_FILE, files, 1); // Write the tar entry entries containing the large file to the tar archive file TEST_FILE
  test_file_extractor(fuzzer); // test the file extractor with the generated tar archive
}

/** 
 * init the path-planning struct
 * 
 * @param[out] fuzzer fuzzer main structure
 **/
Fuzzer* init_fuzzer(){

  Fuzzer *fuzzer;

  fuzzer = (Fuzzer*) malloc(sizeof(Fuzzer));
    
    if (fuzzer == NULL)
    {
		printf("Struct not allocated \n");
		exit(0);
	  }

    fuzzer->crashes_number = 0;
    fuzzer->errors_number = 0;
    fuzzer->no_out_number = 0;

    
    fuzzer->extractor_file = malloc(sizeof(char) * NAME_LEN); // allocate memory for the filename
    if (fuzzer->extractor_file == NULL)
    {
		printf("Array not allocated \n");
		exit(0);
	  }
    memset(fuzzer->extractor_file, 0, NAME_LEN); // initialize the memory to zero

    fuzzer->current_test = malloc(sizeof(char) * NAME_LEN/2); // allocate memory for the filename
    if (fuzzer->current_test == NULL)
    {
		printf("Array not allocated \n");
		exit(0);
	  }
    memset(fuzzer->current_test, 0, NAME_LEN/2); // initialize the memory to zero
  
    return fuzzer;
}

/**
 * close the fuzzer struct (memory released)
 *
 * \param[in] fuzzer fuzzer main structure
**/
void free_fuzzer(Fuzzer *fuzzer)
{
  free(fuzzer->extractor_file);
  free(fuzzer->current_test);
  free(fuzzer);
}

/**
 * This function implements the main fuzzing process for evaluating an extractor.
 * It performs a series of tests on the various fields of a tar header using a fuzzer.
 * The tests include setting names, testing the mode, user ID, group ID, size, modification time,
 * checksum, type flag, link name, magic number, version, and user/group names.
 * Additionally, it tests the end-of-archive and file contents fields.
 * After running the tests, it cleans up any extractor results and outputs the number of tests passed,
 * along with the number of errors and crashes detected by the fuzzer.
 * 
 * @param[in] extractor a pointer to the file path of the extractor being tested
 * 
**/
void fuzz(const char *extractor)
{
  // Initialize a fuzzer struct to keep track of tests and errors.
  Fuzzer *fuzzer;
  fuzzer = init_fuzzer();

  // Copy the filename of the extractor file into the fuzzer struct.
  strcpy(fuzzer->extractor_file, extractor);

  // Print a message to indicate the beginning of the fuzzing process.
  puts("Begin fuzzing...");

  // Start the clock to measure the duration of the fuzzing process.
  clock_t start = clock();

  // Run a series of tests on different fields in the header.
  test_names(0, fuzzer);
  test_mode(fuzzer);
  test_uid(fuzzer);
  test_gid(fuzzer);
  test_size(fuzzer);
  test_mtime(fuzzer);
  test_chksum(fuzzer);
  test_typeflag(fuzzer);
  test_linkname(fuzzer);
  test_magic(fuzzer);
  test_version(fuzzer);
  test_uname(fuzzer, 0);
  test_uname(fuzzer, 1);
  test_end_bytes(fuzzer);
  test_files(fuzzer);

  // Measure the total duration of the fuzzing process.
  clock_t duration = clock() - start;

  // Print a message to indicate that the extractor results are being cleaned up.
  puts("Cleaning extractor results...");

  // Remove any generated files by the extractor and the test file used during the fuzzing process.
  system("rm -rf *" EXT" "TEST_FILE);

  // Print a summary of the results of the fuzzing process.
  printf("\n%u tests passed in %.3f s:\n", fuzzer->errors_number + fuzzer->no_out_number + fuzzer->crashes_number, (float)duration / CLOCKS_PER_SEC);
  printf(KYEL "%u without output" KNRM "\n", fuzzer->no_out_number);
  printf(KRED "%u errors" KNRM " catched by the extractor\n", fuzzer->errors_number);
  printf(KGRN "%u crashes" KNRM " detected by the fuzzer\n", fuzzer->crashes_number);

  // Free up memory used by the fuzzer struct.
  free_fuzzer(fuzzer);
}
