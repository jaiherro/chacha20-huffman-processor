/**
 * file_list.h - Header file for file list management using linked lists
 * 
 * This header file provides the data structures and function prototypes
 * for managing a list of files using a linked list implementation.
 * 
 * Allowed libraries: stdio.h, stdlib.h, string.h, math.h
 */

#ifndef FILE_LIST_H
#define FILE_LIST_H

#include <stddef.h>  /* For size_t */
#include <time.h>    /* For time_t */

/**
 * Maximum length of a filename in the file list
 */
#define FILE_LIST_MAX_FILENAME 256

/**
 * File entry structure
 * Contains information about a processed file
 */
typedef struct file_entry {
    char filename[FILE_LIST_MAX_FILENAME];  /* Filename */
    time_t timestamp;                       /* Processing timestamp */
    size_t original_size;                   /* Original file size */
    size_t processed_size;                  /* Size after processing */
    struct file_entry *next;                /* Pointer to next entry */
} file_entry_t;

/**
 * File list structure
 * Contains the head and tail of the linked list
 */
typedef struct {
    file_entry_t *head;  /* Pointer to the first entry */
    file_entry_t *tail;  /* Pointer to the last entry */
    size_t count;        /* Number of entries in the list */
} file_list_t;

/**
 * Initialize a file list
 * 
 * @param list Pointer to the file list to initialize
 * @return     0 on success, -1 on failure
 */
int file_list_init(file_list_t *list);

/**
 * Add a file to the list
 * 
 * @param list           Pointer to the file list
 * @param filename       Filename to add
 * @param original_size  Original file size
 * @param processed_size Size after processing
 * @return               0 on success, -1 on failure
 */
int file_list_add(file_list_t *list, const char *filename, 
                 size_t original_size, size_t processed_size);

/**
 * Find a file in the list
 * 
 * @param list     Pointer to the file list
 * @param filename Filename to find (can be partial)
 * @return         Pointer to file entry if found, NULL if not found
 */
file_entry_t *file_list_find(file_list_t *list, const char *filename);

/**
 * Get the most recent files in the list
 * 
 * @param list   Pointer to the file list
 * @param count  Maximum number of entries to retrieve
 * @param result Array to store the results (must be pre-allocated)
 * @return       Number of entries retrieved
 */
size_t file_list_get_recent(file_list_t *list, size_t count, file_entry_t **result);

/**
 * Save the file list to a file
 * 
 * @param list     Pointer to the file list
 * @param filename Filename to save to
 * @return         0 on success, -1 on failure
 */
int file_list_save(file_list_t *list, const char *filename);

/**
 * Load the file list from a file
 * 
 * @param list     Pointer to the file list
 * @param filename Filename to load from
 * @return         0 on success, -1 on failure
 */
int file_list_load(file_list_t *list, const char *filename);

/**
 * Free all memory used by the file list
 * 
 * @param list Pointer to the file list
 */
void file_list_free(file_list_t *list);

/**
 * Print the file list to stdout
 * 
 * @param list Pointer to the file list
 */
void file_list_print(file_list_t *list);

#endif /* FILE_LIST_H */