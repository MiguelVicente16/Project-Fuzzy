#ifndef TEST_H
#define TEST_H



#define EXT ".txt" //extension to put at the end of file to easily clean



typedef struct {
  const char* name;
  void (*test)(Fuzzer* fuzzer, char *field, unsigned size);
} Test;

typedef struct {
  const char* name;
  void (*test)(Fuzzer* fuzzer, char *field);
} Test_time;


void test_empty(Fuzzer* fuzzer, char *field, unsigned size);
void test_not_numeric(Fuzzer* fuzzer, char *field, unsigned size);
void test_big(Fuzzer* fuzzer, char *field, unsigned size);
void test_not_octal(Fuzzer* fuzzer, char *field, unsigned size);
void test_not_terminated(Fuzzer* fuzzer, char *field, unsigned size);
void test_middle_null_termination(Fuzzer* fuzzer, char *field, unsigned size);
void test_0_and_middle_null_termination(Fuzzer* fuzzer, char *field, unsigned size);
void test_not_ascii(Fuzzer* fuzzer, char *field, unsigned size);
void test_all_0(Fuzzer* fuzzer, char *field, unsigned size);
void test_all_null_but_end_0(Fuzzer* fuzzer, char *field, unsigned size);
void test_forbidden_char(Fuzzer* fuzzer, const char *field_name, char *field);
void test_weird_characters(Fuzzer* fuzzer, const char *field_name, char *field, unsigned size);
void test_fill_all(Fuzzer* fuzzer, char *field, unsigned size);
void test_directory(Fuzzer* fuzzer, char *field, unsigned size);
void test_current_time(Fuzzer* fuzzer, char *field);
void test_50h_future(Fuzzer* fuzzer, char *field);
void test_50h_past(Fuzzer* fuzzer, char *field);
void test_far_future(Fuzzer* fuzzer, char *field);
#endif