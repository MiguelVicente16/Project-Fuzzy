#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "fuzzer.h"
#include "tar.h"
#include "test.h"

// Test case: empty field
void test_empty(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, 0, size);
  test_header(fuzzer);
}

// Test case: non-numeric field
void test_not_numeric(Fuzzer* fuzzer, char *field, unsigned size) {
  size = 5;
  memcpy(field, "hello", size);
  test_header(fuzzer);
}

// Test case: field filled with the maximum digit '7'
void test_big(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, '7', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);
}

// Test case: field filled with non-octal digit '9'
void test_not_octal(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, '9', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);
}

// Test case: field not terminated with a null character
void test_not_terminated(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, '4', size);
  test_header(fuzzer);
}

// Test case: field with a null character in the middle, but not at the end
void test_middle_null_termination(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, 0, size);
  memset(field, '2', size / 2);
  test_header(fuzzer);
}


// Test case: field with a null character in the middle and at the end
void test_0_and_middle_null_termination(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, 0, size);
  memset(field, '0', size / 2);
  test_header(fuzzer);
}

// Test case: field containing non-ASCII character
void test_not_ascii(Fuzzer* fuzzer, char *field, unsigned size) {
  strncpy(field, "😋🥵😎" EXT, size);

  test_header(fuzzer);
}

// Test case: field filled with '0' character
void test_all_0(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, '0', size - 1);
  field[size - 1] = 0;
  test_header(fuzzer);
}

// Test case: field with all null characters except for the last one, which is '0'
void test_all_null_but_end_0(Fuzzer* fuzzer, char *field, unsigned size) {
  memset(field, 0, size - 1);
  field[size - 1] = '0';
  test_header(fuzzer);
}

// Test case: field with forbidden characters
void test_forbidden_char(Fuzzer* fuzzer, const char *field_name, char *field) {
   char forbidden_char[] = {'*', '\\', '/', '"', '?', ' '};
      for (unsigned i = 0; i < sizeof(forbidden_char); i++)
      {
        field[0] = forbidden_char[i];
        sprintf(fuzzer->current_test, "%s_weird_char='%c'", field_name, field[0]);
        test_header(fuzzer);
      }
}

// Test case: field with weird characters
void test_weird_characters(Fuzzer* fuzzer, const char *field_name, char *field, unsigned size) {
      strncpy(field, "0" EXT, size);

      static const int WEIRD_CHARS_LEN = 161;
      char WEIRD_CHARS[WEIRD_CHARS_LEN];

      int i, j = 0;
      for (i = 0; i <= 31; i++) {
          WEIRD_CHARS[j++] = (char)i;
      }

      for (i = 127; i <= 255; i++) {
          WEIRD_CHARS[j++] = (char)i;
      }

      for (unsigned k = 0; k < sizeof(WEIRD_CHARS); k++)
      {
        field[0] = WEIRD_CHARS[k];
        sprintf(fuzzer->current_test, "%s_weird_char='%c'", field_name, field[0]);
        test_header(fuzzer);
      }
}

// Test case: field with a string of zeros
void test_fill_all(Fuzzer* fuzzer, char *field, unsigned size) {
      sprintf(field, "%0*d" EXT, (int)(size - strlen(EXT) - 1), 0);
      test_header(fuzzer);
}

// Test case: field as a directory
void test_directory(Fuzzer* fuzzer,  char *field, unsigned size) {
      strncpy(field, "tests" EXT "/", size);
      test_header(fuzzer);
}

// Test case: field with the current time
void test_current_time(Fuzzer* fuzzer,char *field) {
    sprintf(field, "%lo", (unsigned long)time(NULL));
    test_header(fuzzer);
}

// Test case: field with a time 50 hours in the future
void test_50h_future(Fuzzer* fuzzer, char *field) {
    sprintf(field, "%lo", (unsigned long)time(NULL) + 50 * 3600);
    test_header(fuzzer);
}

// Test case: field with a time 50 hours in the past
void test_50h_past(Fuzzer* fuzzer,  char *field) {
  sprintf(field, "%lo", (unsigned long)time(NULL) - 50 * 3600);
  test_header(fuzzer);
}

// Test case: field with a time far in the future
void test_far_future(Fuzzer* fuzzer, char *field) {
  sprintf(field, "%lo", (unsigned long)time(NULL) * 2);
  test_header(fuzzer);
}