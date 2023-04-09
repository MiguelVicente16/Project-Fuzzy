#ifndef FUZZ_H
#define FUZZ_H

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define EXT ".txt" //extension to put at the end of file to easily clean

#define TEST_FILE "test.tar"
#define CRASH_MSG "*** The program has crashed ***\n"
#define LEN_CRASH_MSG strlen(CRASH_MSG) + 1

typedef struct
{
    int errors_number;
    int no_out_number;
    int crashes_number;
    char *extractor_file;
    char *current_test;
} Fuzzer;


int test_file_extractor(Fuzzer* fuzzer);
void test_header(Fuzzer *fuzzer);
void set_name(Fuzzer* fuzzer, const char *name, const char *field_name);
void generic_field_tests(Fuzzer* fuzzer, const char *field_name, char *field, unsigned size);
void test_names(int linkname, Fuzzer *fuzzer);
void test_mode(Fuzzer *fuzzer);
void test_uid(Fuzzer* fuzzer);
void test_gid(Fuzzer* fuzzer);
void test_size(Fuzzer* fuzzer);
void test_mtime(Fuzzer* fuzzer);
void test_chksum(Fuzzer* fuzzer);
void test_typeflag(Fuzzer* fuzzer);
void test_linkname(Fuzzer* fuzzer);
void test_magic(Fuzzer* fuzzer);
void test_version(Fuzzer* fuzzer);
void test_uname(Fuzzer* fuzzer, int gname);
void test_end_bytes(Fuzzer* fuzzer);
void test_files(Fuzzer* fuzzer);
Fuzzer* init_fuzzer();
void free_fuzzer(Fuzzer *fuzzer);
void fuzz(const char* extractor);

#endif