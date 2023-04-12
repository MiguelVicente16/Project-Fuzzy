#ifndef TAR_H
#define TAR_H

#define NAME_LEN 100
#define MODE_LEN 8
#define UID_LEN 8
#define GID_LEN 8
#define SIZE_LEN 12
#define MTIME_LEN 12
#define CHKSUM_LEN 8
#define LINKNAME_LEN NAME_LEN
#define MAGIC_LEN 6
#define VERSION_LEN 2
#define UNAME_LEN 32
#define GNAME_LEN UNAME_LEN

#define END_LEN 1024

typedef struct
{                                /* byte offset */
    char name[NAME_LEN];         /*   0 */
    char mode[MODE_LEN];         /* 100 */
    char uid[UID_LEN];           /* 108 */
    char gid[GID_LEN];           /* 116 */
    char size[SIZE_LEN];         /* 124 */
    char mtime[MTIME_LEN];       /* 136 */
    char chksum[CHKSUM_LEN];     /* 148 */
    char typeflag;               /* 156 */
    char linkname[LINKNAME_LEN]; /* 157 */
    char magic[MAGIC_LEN];       /* 257 */
    char version[VERSION_LEN];   /* 263 */
    char uname[UNAME_LEN];       /* 265 */
    char gname[GNAME_LEN];       /* 297 */
    char devmajor[8];            /* 329 */
    char devminor[8];            /* 337 */
    char prefix[155];            /* 345 */
    char padding[12];            /* 500 */
} tar_t;

typedef struct
{
    tar_t header;
    char *content;
    size_t size;
} tar_entry;


/* Bits used in the mode field, values in octal.  */
#define TSUID 04000   /* set UID on execution */
#define TSGID 02000   /* set GID on execution */
#define TSVTX 01000   /* reserved */
                      /* file permissions */
#define TUREAD 00400  /* read by owner */
#define TUWRITE 00200 /* write by owner */
#define TUEXEC 00100  /* execute/search by owner */
#define TGREAD 00040  /* read by group */
#define TGWRITE 00020 /* write by group */
#define TGEXEC 00010  /* execute/search by group */
#define TOREAD 00004  /* read by other */
#define TOWRITE 00002 /* write by other */
#define TOEXEC 00001  /* execute/search by other */
#define TOTRY 00214  /* execute/search by other */

#define TMAGIC   "ustar"        /* ustar and a null */
#define TVERSION "00"           /* 00 and no null */

/* Values used in typeflag field.  */
#define REGTYPE  '0'            /* regular file */
#define AREGTYPE '\0'           /* regular file */
#define LNKTYPE  '1'            /* link */
#define SYMTYPE  '2'            /* reserved */
#define CHRTYPE  '3'            /* character special */
#define BLKTYPE  '4'            /* block special */
#define DIRTYPE  '5'            /* directory */
#define FIFOTYPE '6'            /* FIFO special */
#define CONTTYPE '7'            /* reserved */
#define XHDTYPE  'x'            /* Extended header referring to the next file in the archive */
#define XGLTYPE  'g'            /* Global extended header */

#define BLOCKSIZE 512

// It's set to "docheck" to signal that the write functions will compute the checksum before writing it to the header. 
// In other words, this value indicates that the checksum has not been computed yet and it needs to be calculated before 
// writing the tar file.
#define DO_CHKSUM "docheck" 

tar_t* set_corrupted_header(tar_t *header);
void free_corrupted_header(tar_t *header);
unsigned int calculate_checksum(tar_t* entry);
void set_size_header(tar_t *header, size_t size);
void set_header(tar_t *header);
void write_tar_header(FILE *file, tar_t *header);
void write_tar_fields(const char *filename, tar_t *header, const char *buffer, size_t size, const char *end_bytes, size_t end_size);
void write_tar_entries(const char *filename, tar_entry entries[], size_t count);
#endif