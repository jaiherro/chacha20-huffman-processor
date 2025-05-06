/**
 * file_list.c - Implementation of file list management using linked lists
 * 
 * This file implements the functions for managing a list of files
 * using a linked list data structure.
 * 
 * Only uses the following standard C libraries as required:
 * - stdio.h (for file I/O and printing)
 * - stdlib.h (for memory allocation)
 * - string.h (for string operations)
 */

#include "utils/file_list.h"
#include <stdio.h>   /* For file I/O and printing */
#include <stdlib.h>  /* For memory allocation */
#include <string.h>  /* For string operations */

/* Debug printing support */
#ifdef FILE_LIST_DEBUG
#define DEBUG_PRINT(...) printf("[FileList] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

int file_list_init(file_list_t *list) {
    if (list == NULL) {
        return -1;
    }
    
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1; // Start with sequence number 1
    
    DEBUG_PRINT("Initialized empty file list\n");
    
    return 0;
}

int file_list_add(file_list_t *list, const char *filename, 
                 size_t original_size, size_t processed_size) {
    file_entry_t *new_entry;
    
    if (list == NULL || filename == NULL) {
        return -1;
    }
    
    /* Allocate memory for the new entry */
    new_entry = (file_entry_t *)malloc(sizeof(file_entry_t));
    if (new_entry == NULL) {
        return -1;
    }
    
    /* Initialize the new entry */
    strncpy(new_entry->filename, filename, FILE_LIST_MAX_FILENAME - 1);
    new_entry->filename[FILE_LIST_MAX_FILENAME - 1] = '\0'; /* Ensure null-termination */
    new_entry->sequence_num = list->next_sequence_num++; // Assign and increment sequence number
    new_entry->original_size = original_size;
    new_entry->processed_size = processed_size;
    new_entry->next = NULL;
    
    /* Add to the end of the list */
    if (list->tail == NULL) {
        /* Empty list */
        list->head = new_entry;
        list->tail = new_entry;
    } else {
        /* Non-empty list */
        list->tail->next = new_entry;
        list->tail = new_entry;
    }
    
    list->count++;
    
    DEBUG_PRINT("Added file '%s' to list (entry count: %zu)\n", 
                filename, list->count);
    
    return 0;
}

file_entry_t *file_list_find(file_list_t *list, const char *filename) {
    file_entry_t *current;
    
    if (list == NULL || filename == NULL) {
        return NULL;
    }
    
    /* Traverse the list and look for a matching filename */
    current = list->head;
    while (current != NULL) {
        /* Check if current filename contains the search string */
        if (strstr(current->filename, filename) != NULL) {
            DEBUG_PRINT("Found matching file: '%s'\n", current->filename);
            return current;
        }
        current = current->next;
    }
    
    DEBUG_PRINT("No matching file found for '%s'\n", filename);
    
    return NULL;
}

size_t file_list_get_recent(file_list_t *list, size_t count, file_entry_t **result) {
    file_entry_t *current;
    size_t result_count = 0;
    
    if (list == NULL || result == NULL || count == 0) {
        return 0;
    }
    
    /* If the list has fewer entries than requested, return all entries */
    if (list->count <= count) {
        current = list->head;
        result_count = 0;
        
        while (current != NULL) {
            result[result_count++] = current;
            current = current->next;
        }
        
        return result_count;
    }
    
    /* Otherwise, find the most recent entries based on sequence number */
    /* Initialize result array with NULL pointers */
    for (size_t i = 0; i < count; i++) {
        result[i] = NULL;
    }
    
    /* Scan through the list */
    current = list->head;
    while (current != NULL) {
        /* Find the position to insert this entry based on sequence number */
        for (size_t i = 0; i < count; i++) {
            if (result[i] == NULL || current->sequence_num > result[i]->sequence_num) {
                /* Shift existing entries down */
                for (size_t j = count - 1; j > i; j--) {
                    result[j] = result[j - 1];
                }
                
                /* Insert this entry */
                result[i] = current;
                break;
            }
        }
        
        current = current->next;
    }
    
    /* Count the number of valid entries in the result array */
    result_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (result[i] != NULL) {
            result_count++;
        }
    }
    
    DEBUG_PRINT("Retrieved %zu recent files\n", result_count);
    
    return result_count;
}

int file_list_save(file_list_t *list, const char *filename) {
    FILE *file;
    file_entry_t *current;
    
    if (list == NULL || filename == NULL) {
        return -1;
    }
    
    /* Open the file for writing */
    file = fopen(filename, "wb");
    if (file == NULL) {
        DEBUG_PRINT("Failed to open file '%s' for writing\n", filename);
        return -1;
    }
    
    /* Write the number of entries and next sequence number */
    if (fwrite(&list->count, sizeof(size_t), 1, file) != 1 ||
        fwrite(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1) {
        DEBUG_PRINT("Failed to write header to file\n");
        fclose(file);
        return -1;
    }
    
    /* Write each entry */
    current = list->head;
    while (current != NULL) {
        /* Write the filename length */
        size_t filename_len = strlen(current->filename) + 1;
        if (fwrite(&filename_len, sizeof(size_t), 1, file) != 1) {
            DEBUG_PRINT("Failed to write filename length to file\n");
            fclose(file);
            return -1;
        }
        
        /* Write the filename */
        if (fwrite(current->filename, 1, filename_len, file) != filename_len) {
            DEBUG_PRINT("Failed to write filename to file\n");
            fclose(file);
            return -1;
        }
        
        /* Write the rest of the entry data */
        if (fwrite(&current->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(&current->original_size, sizeof(size_t), 1, file) != 1 ||
            fwrite(&current->processed_size, sizeof(size_t), 1, file) != 1) {
            DEBUG_PRINT("Failed to write entry data to file\n");
            fclose(file);
            return -1;
        }
        
        current = current->next;
    }
    
    fclose(file);
    
    DEBUG_PRINT("Saved %zu entries to file '%s'\n", list->count, filename);
    
    return 0;
}

int file_list_load(file_list_t *list, const char *filename) {
    FILE *file;
    size_t count, i;
    
    if (list == NULL || filename == NULL) {
        return -1;
    }
    
    /* Clear any existing entries */
    file_list_free(list);
    
    /* Open the file for reading */
    file = fopen(filename, "rb");
    if (file == NULL) {
        DEBUG_PRINT("Failed to open file '%s' for reading\n", filename);
        return -1;
    }
    
    /* Read the number of entries and next sequence number */
    if (fread(&count, sizeof(size_t), 1, file) != 1 ||
        fread(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1) {
        DEBUG_PRINT("Failed to read header from file\n");
        fclose(file);
        return -1;
    }
    
    /* Read each entry */
    for (i = 0; i < count; i++) {
        file_entry_t *new_entry;
        size_t filename_len;
        
        /* Read the filename length */
        if (fread(&filename_len, sizeof(size_t), 1, file) != 1) {
            DEBUG_PRINT("Failed to read filename length from file\n");
            fclose(file);
            return -1;
        }
        
        /* Allocate memory for the new entry */
        new_entry = (file_entry_t *)malloc(sizeof(file_entry_t));
        if (new_entry == NULL) {
            DEBUG_PRINT("Failed to allocate memory for entry\n");
            fclose(file);
            return -1;
        }
        
        /* Read the filename */
        if (fread(new_entry->filename, 1, filename_len, file) != filename_len) {
            DEBUG_PRINT("Failed to read filename from file\n");
            free(new_entry);
            fclose(file);
            return -1;
        }
        
        /* Read the rest of the entry data */
        if (fread(&new_entry->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fread(&new_entry->original_size, sizeof(size_t), 1, file) != 1 ||
            fread(&new_entry->processed_size, sizeof(size_t), 1, file) != 1) {
            DEBUG_PRINT("Failed to read entry data from file\n");
            free(new_entry);
            fclose(file);
            return -1;
        }
        
        /* Set next pointer to NULL */
        new_entry->next = NULL;
        
        /* Add to the end of the list */
        if (list->tail == NULL) {
            /* Empty list */
            list->head = new_entry;
            list->tail = new_entry;
        } else {
            /* Non-empty list */
            list->tail->next = new_entry;
            list->tail = new_entry;
        }
        
        list->count++;
    }
    
    fclose(file);
    
    DEBUG_PRINT("Loaded %zu entries from file '%s'\n", list->count, filename);
    
    return 0;
}

void file_list_free(file_list_t *list) {
    file_entry_t *current, *next;
    
    if (list == NULL) {
        return;
    }
    
    /* Free all entries */
    current = list->head;
    while (current != NULL) {
        next = current->next;
        free(current);
        current = next;
    }
    
    /* Reset list */
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1; // Reset sequence number too
    
    DEBUG_PRINT("Freed file list\n");
}

void file_list_print(file_list_t *list) {
    file_entry_t *current;
    
    if (list == NULL) {
        printf("File list is NULL\n");
        return;
    }
    
    printf("File list (%zu entries):\n", list->count);
    
    if (list->count == 0) {
        printf("  (empty)\n");
        return;
    }
    
    current = list->head;
    while (current != NULL) {
        /* Print the entry */
        printf("--> %s\n", current->filename);
        printf("    Sequence: #%lu\n", current->sequence_num);
        printf("    Original size: %zu bytes\n", current->original_size);
        printf("    Processed size: %zu bytes\n", current->processed_size);
        printf("    Compression ratio: %.2f%%\n",
               100.0 * (double)current->processed_size / (double)current->original_size);
        
        current = current->next;
    }
}
