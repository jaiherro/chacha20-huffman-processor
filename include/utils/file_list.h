/*
 * file_list.h - File list management using linked lists
 */

#ifndef FILE_LIST_H
#define FILE_LIST_H

#define FILE_LIST_MAX_FILENAME 256

/* File entry structure */
typedef struct file_entry
{
    char input_filename[FILE_LIST_MAX_FILENAME];
    char output_filename[FILE_LIST_MAX_FILENAME];
    unsigned long sequence_num;
    unsigned long original_size;
    unsigned long processed_size;
    struct file_entry *next;
} file_entry_t;

/* File list structure */
typedef struct
{
    file_entry_t *head;
    file_entry_t *tail;
    unsigned long count;
    unsigned long next_sequence_num;
} file_list_t;

/* Initialise file list */
int file_list_init(file_list_t *list);

/* Add file to list */
int file_list_add(file_list_t *list, const char *input_filename,
                  const char *output_filename, unsigned long original_size,
                  unsigned long processed_size);

/* Find file in list by name */
file_entry_t *file_list_find(file_list_t *list, const char *filename);

/* Get most recent files */
unsigned long file_list_get_recent(file_list_t *list, unsigned long count,
                                   file_entry_t **result);

/* Save list to file */
int file_list_save(file_list_t *list, const char *filename);

/* Load list from file */
int file_list_load(file_list_t *list, const char *filename);

/* Free list memory */
void file_list_free(file_list_t *list);

/* Print list to stdout */
void file_list_print(file_list_t *list);

#endif /* FILE_LIST_H */
