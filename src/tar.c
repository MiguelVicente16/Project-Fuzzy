#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "fuzzer.h"
#include "tar.h"
#include "test.h"


/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(tar_t* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}

/**
 * Sets the size field in the tar header to the given size 
 * @param[in] header A pointer to the tar header structure.
 * @param[in] size size of the header we want
 **/
void set_size_header(tar_t *header, size_t size)
{
  /* 
    The size field in the tar header is a null-padded octal string representation
    of the file size, stored in 11 bytes with the last byte being a null byte. 
    Here we use sprintf to convert the given size to a null-padded octal string 
    with the appropriate number of digits (SIZE_LEN - 1) and store it in the 
    header's size field. 
  */
  sprintf(header->size, "%0*lo", SIZE_LEN - 1, size);
}

/**
 * Function to set the tar header with some arbitrary values on the required fields.
 * @param[in] header A pointer to the tar header structure.
**/
void set_header(tar_t *header)
{
  // Set all the fields of the header to zero.
  memset(header, 0, sizeof(tar_t));

  // Set the name field to a randomly generated string with the EXT extension.
  sprintf(header->name, "name_%06u" EXT, rand() % 1000000);

  // Set the file mode to 777 permision:(owner:rwx; group:rwx; others:rwx).
  sprintf(header->mode, "0000777");

  // Set the user ID and group ID to 1000.
  // The owner and group of the file contained in the archive are both daemon.
  sprintf(header->uid, "0001000");
  sprintf(header->gid, "0001000");

  // Set the size field to 0.
  set_size_header(header, 0);

  // Set the modification time to 0.
  sprintf(header->mtime, "0");

  // Set the checksum field to DO_CHKSUM to signal that the write functions below will compute the checksum.
  sprintf(header->chksum, DO_CHKSUM);

  // Set the type flag to REGTYPE for a regular file.
  header->typeflag = REGTYPE;

  // Set the magic field to TMAGIC. 
  // Specifies the format of the tar archive.
  sprintf(header->magic, TMAGIC);

  // Set the version field to TVERSION.
  memcpy(header->version, TVERSION, VERSION_LEN);

  // Set the user and group name to "user".
  sprintf(header->uname, "user");
  sprintf(header->gname, "user");

  // Set the device major and minor numbers to 0.
  // Convention to indicate that the file is not associated with any particular device.
  sprintf(header->devmajor, "0000000");
  sprintf(header->devminor, "0000000");
}

/**
 *  Writes a tar_t and the content of a file in a tar archive.
 * 
 *  @param[in] filename: path of the tar archive
 *  @param[in] header: tar_t structure representing the file to be added to the archive
 *  @param[in] buffer: content of the file to be added to the archive
 *  @param[in] size: size of the file to be added to the archive
 * 
 *  The function first initializes an array of END_LEN bytes called end_bytes with zeros.
 *  It then calls the write_tar_fields function to write the file header, content, and end bytes
 *  to the tar archive. The end_bytes array is used to ensure that the archive has a size that
 *  is a multiple of the tar block size.
 *  @see write_tar_fields
**/
void write_tar(const char *filename, tar_t *header, const char *buffer, size_t size) {
  char end_bytes[END_LEN];
  memset(end_bytes, 0, END_LEN);

  write_tar_fields(filename, header, buffer, size, end_bytes, END_LEN);
}

/**
 * Writes a tar header to a file, computing the checksum if it is set to DO_CHKSUM
 *
 * @param f: the file to write the header to
 * @param header: the header to write
 */
void write_tar_header(FILE *file, tar_t *header)
{
  // If the checksum is set to DO_CHKSUM, calculate it before writing the header to the file
  if (strncmp(DO_CHKSUM, header->chksum, CHKSUM_LEN) == 0)
  {
    // Save the old checksum so it can be restored after computing the new checksum
    char old_checksum[CHKSUM_LEN];
    strncpy(old_checksum, header->chksum, CHKSUM_LEN);

    // Compute the new checksum
    calculate_checksum(header);

    // Write the header with the new checksum to the file
    fwrite(header, sizeof(tar_t), 1, file);

    // Restore the old checksum value in the header 
    // to maintain the consistency of the header's data
    strncpy(header->chksum, old_checksum, CHKSUM_LEN);
    return;
  }

  // If the checksum is not set to DO_CHKSUM, write the header to the file without computing the checksum
  fwrite(header, sizeof(tar_t), 1, file);
}

/**
  * Writes the tar_t header of a file followed by the file content and end bytes to an archive file.
  * 
  * @param[in] filename: path of the archive file to write to.
  * @param[in] header: pointer to the tar_t struct representing the file header.
  * @param[in] buffer: pointer to the buffer holding the file content.
  * @param[in] size: size of the file content in bytes.
  * @param[in] end_bytes: pointer to the buffer holding the end bytes to be added after the file content.
  * @param[in] end_size: size of the end bytes buffer in bytes.
  * 
  * @see write_tar_header
**/
void write_tar_fields(const char *filename, tar_t *header, const char *buffer, size_t size, const char *end_bytes, size_t end_size)
{
  // open the archive file in binary write mode
  FILE *file = fopen(filename, "wb");
  if (!file)
  {
    printf("Could not write to file");
    return;
  }

  // write the file header to the archive file
  write_tar_header(file, header);

  // write the file content to the archive file
  fwrite(buffer, size, 1, file);

  // write the end bytes to the archive file
  fwrite(end_bytes, end_size, 1, file);

  // close the archive file
  fclose(file);
}

/**
 * Write a number of tar entries defined by the variable count in a file. 
 * It uses the field size in entries to set the field size in the header
 * Also adds the appropriate number of null bytes at the end.
 * This function frees the pointer of each entries[].content
 *
 * @param[in] filename: path of the tar archive to write to
 * @param[in] entries: array of tar_entry structs representing the entries to write
 * @param[in] count: number of entries in the entries array
 */
void write_tar_entries(const char *filename, tar_entry entries[], size_t count)
{
  // Open the file for writing in binary mode
  FILE *f = fopen(filename, "wb");
  if (!f)
  {
    printf("Could not write to file");
    return;
  }

  // Loop through each entry in the array and write its header and content
  for (size_t i = 0; i < count; i++)
  {
    tar_entry *e = &entries[i];
    // Set the size field in the header to the size of the content
    set_size_header(&e->header, e->size);
    // Write the header to the file, computing the checksum if necessary
    write_tar_header(f, &e->header);

    // Write the content of the entry to the file
    fwrite(e->content, e->size, 1, f);
    // Free the content pointer, since we no longer need it
    if (e->content)
    {
      free(e->content);
    }

    // Compute the number of null bytes needed to pad the content to a multiple of 512 bytes
    unsigned size_padding = 512 - (e->size % 512);
    char padding[size_padding];

    memset(padding, 0, size_padding);
    // Write the null bytes to the file as padding
    fwrite(padding, size_padding, 1, f);
  }

  // Write the end-of-archive null bytes to the file
  char end_bytes[END_LEN];
  memset(end_bytes, 0, END_LEN);
  fwrite(end_bytes, END_LEN, 1, f);

  // Close the file
  fclose(f);
}
