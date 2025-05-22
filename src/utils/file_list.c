/**
 * file_list.c - Implementation of file list management using linked lists
 * * This file implements the functions for managing a list of files
 * using a linked list data structure.
 * * Only uses the following standard C libraries as required:
 * - stdio.h (for file I/O and printing)
 * - stdlib.h (for memory allocation)
 * - string.h (for string operations)
 */

#include "utils/file_list.h"
#include <stdio.h>  /* For file I/O and printing */
#include <stdlib.h> /* For memory allocation */
#include <string.h> /* For string operations */

/* Debug printing support */
#ifdef FILE_LIST_DEBUG
#define DEBUG_PRINT(...) printf("[FileList] " __VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

int file_list_init(file_list_t *list)
{
    if (list == NULL)
    {
        return -1;
    }

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1; // Start with sequence number 1

    DEBUG_PRINT("Initialized empty file list\n");

    return 0;
}

// Replaced size_t with unsigned long for original_size and processed_size
int file_list_add(file_list_t *list, const char *filename,
                  unsigned long original_size, unsigned long processed_size)
{
    file_entry_t *new_entry;

    if (list == NULL || filename == NULL)
    {
        return -1;
    }

    /* Allocate memory for the new entry */
    new_entry = (file_entry_t *)malloc(sizeof(file_entry_t));
    if (new_entry == NULL)
    {
        DEBUG_PRINT("Error: malloc failed for new file entry.\n");
        return -1;
    }

    /* Initialize the new entry */
    strncpy(new_entry->filename, filename, FILE_LIST_MAX_FILENAME - 1);
    new_entry->filename[FILE_LIST_MAX_FILENAME - 1] = '\0'; /* Ensure null-termination */
    new_entry->sequence_num = list->next_sequence_num++;    // Assign and increment sequence number
    new_entry->original_size = original_size;
    new_entry->processed_size = processed_size;
    new_entry->next = NULL;

    /* Add to the end of the list */
    if (list->tail == NULL)
    {
        /* Empty list */
        list->head = new_entry;
        list->tail = new_entry;
    }
    else
    {
        /* Non-empty list */
        list->tail->next = new_entry;
        list->tail = new_entry;
    }

    list->count++;

    DEBUG_PRINT("Added file '%s' to list (entry count: %lu)\n",
                filename, list->count); // Use %lu for unsigned long

    return 0;
}

file_entry_t *file_list_find(file_list_t *list, const char *filename)
{
    file_entry_t *current;

    if (list == NULL || filename == NULL)
    {
        return NULL;
    }

    /* Traverse the list and look for a matching filename */
    current = list->head;
    while (current != NULL)
    {
        /* Check if current filename contains the search string */
        if (strstr(current->filename, filename) != NULL)
        {
            DEBUG_PRINT("Found matching file: '%s'\n", current->filename);
            return current;
        }
        current = current->next;
    }

    DEBUG_PRINT("No matching file found for '%s'\n", filename);

    return NULL;
}

// Replaced size_t with unsigned long for count and return type
unsigned long file_list_get_recent(file_list_t *list, unsigned long count, file_entry_t **result)
{
    file_entry_t *current;
    unsigned long result_count = 0; // Replaced size_t with unsigned long
    unsigned long i, j;             // Loop variables - Replaced size_t with unsigned long

    if (list == NULL || result == NULL || count == 0)
    {
        return 0;
    }

    /* If the list has fewer entries than requested, return all entries */
    if (list->count <= count)
    {
        current = list->head;
        result_count = 0;

        while (current != NULL && result_count < list->count)
        { // Ensure not to write past allocated 'result' if 'count' was smaller
            result[result_count++] = current;
            current = current->next;
        }

        return result_count;
    }

    /* Otherwise, find the most recent entries based on sequence number */
    /* This is a simple (but potentially inefficient for large lists/counts) way to get top N.
       A min-priority queue of size 'count' would be more efficient.
       The current implementation iterates through the list and maintains a sorted array of 'count' recent items.
    */
    /* Initialize result array with NULL pointers */
    for (i = 0; i < count; i++)
    {
        result[i] = NULL;
    }

    /* Scan through the list */
    current = list->head;
    while (current != NULL)
    {
        /* Find the position to insert this entry based on sequence number (descending) */
        for (i = 0; i < count; i++)
        {
            if (result[i] == NULL || current->sequence_num > result[i]->sequence_num)
            {
                /* Shift existing entries down */
                for (j = count - 1; j > i; j--)
                {
                    result[j] = result[j - 1];
                }

                /* Insert this entry */
                result[i] = current;
                if (result_count < count)
                    result_count++; // Track actual items inserted if fewer than 'count'
                break;
            }
        }
        current = current->next;
    }

    // The result_count might be more accurate if we count non-NULLs after the loop
    result_count = 0;
    for (i = 0; i < count; i++)
    {
        if (result[i] != NULL)
        {
            result_count++;
        }
        else
        {
            break; // Array is sorted by recency (or NULLs at end)
        }
    }

    DEBUG_PRINT("Retrieved %lu recent files\n", result_count); // Use %lu

    return result_count;
}

int file_list_save(file_list_t *list, const char *filename)
{
    FILE *file;
    file_entry_t *current;

    if (list == NULL || filename == NULL)
    {
        return -1;
    }

    /* Open the file for writing */
    file = fopen(filename, "wb"); // Binary mode
    if (file == NULL)
    {
        DEBUG_PRINT("Failed to open file '%s' for writing\n", filename);
        return -1;
    }

    /* Write the number of entries (unsigned long) and next sequence number (unsigned long) */
    if (fwrite(&list->count, sizeof(unsigned long), 1, file) != 1 || // Replaced size_t with unsigned long
        fwrite(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1)
    {
        DEBUG_PRINT("Failed to write header to file\n");
        fclose(file);
        return -1;
    }

    /* Write each entry */
    current = list->head;
    while (current != NULL)
    {
        /* Write the filename length (use unsigned long for consistency, though strlen returns size_t) */
        unsigned long filename_len_ul = strlen(current->filename) + 1; // +1 for null terminator
        if (fwrite(&filename_len_ul, sizeof(unsigned long), 1, file) != 1)
        { // Replaced size_t with unsigned long
            DEBUG_PRINT("Failed to write filename length to file\n");
            fclose(file);
            return -1;
        }

        /* Write the filename */
        if (fwrite(current->filename, 1, filename_len_ul, file) != filename_len_ul)
        {
            DEBUG_PRINT("Failed to write filename to file\n");
            fclose(file);
            return -1;
        }

        /* Write the rest of the entry data (sequence_num, original_size, processed_size) */
        if (fwrite(&current->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(&current->original_size, sizeof(unsigned long), 1, file) != 1 || // Replaced size_t with unsigned long
            fwrite(&current->processed_size, sizeof(unsigned long), 1, file) != 1)
        { // Replaced size_t with unsigned long
            DEBUG_PRINT("Failed to write entry data to file\n");
            fclose(file);
            return -1;
        }

        current = current->next;
    }

    fclose(file);

    DEBUG_PRINT("Saved %lu entries to file '%s'\n", list->count, filename); // Use %lu

    return 0;
}

int file_list_load(file_list_t *list, const char *filename)
{
    FILE *file;
    unsigned long count_from_file, i; // Replaced size_t with unsigned long

    if (list == NULL || filename == NULL)
    {
        return -1;
    }

    /* Clear any existing entries by re-initializing */
    file_list_free(list); // This also calls file_list_init essentially
    // file_list_init(list); // Ensure it's pristine if free doesn't init fully

    /* Open the file for reading */
    file = fopen(filename, "rb"); // Binary mode
    if (file == NULL)
    {
        DEBUG_PRINT("File list '%s' not found or cannot be opened for reading. Creating new list.\n", filename);
        // Not an error, just means no list to load. List is already initialized and empty.
        return 0; // Return success as an empty list is valid
    }

    /* Read the number of entries and next sequence number */
    if (fread(&count_from_file, sizeof(unsigned long), 1, file) != 1 || // Replaced size_t with unsigned long
        fread(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1)
    {
        DEBUG_PRINT("Failed to read header from file '%s'. File might be corrupted or empty.\n", filename);
        fclose(file);
        // If header read fails, treat as if file didn't exist or was invalid.
        // List is already initialized to empty.
        return 0; // Consider this a "valid" outcome (empty list loaded) rather than error.
                  // Or return -1 if strict error on bad format. Let's be lenient.
    }

    /* Read each entry */
    for (i = 0; i < count_from_file; i++)
    {
        file_entry_t *new_entry;
        unsigned long filename_len_ul; // Replaced size_t with unsigned long

        /* Read the filename length */
        if (fread(&filename_len_ul, sizeof(unsigned long), 1, file) != 1)
        { // Replaced size_t with unsigned long
            DEBUG_PRINT("Failed to read filename length from file (entry %lu)\n", i);
            fclose(file);
            file_list_free(list); // Clean up partially loaded list
            return -1;            // Error in format
        }

        if (filename_len_ul == 0 || filename_len_ul > FILE_LIST_MAX_FILENAME)
        {
            DEBUG_PRINT("Invalid filename length %lu read from file (entry %lu)\n", filename_len_ul, i);
            fclose(file);
            file_list_free(list);
            return -1;
        }

        /* Allocate memory for the new entry */
        new_entry = (file_entry_t *)malloc(sizeof(file_entry_t));
        if (new_entry == NULL)
        {
            DEBUG_PRINT("Failed to allocate memory for entry %lu\n", i);
            fclose(file);
            file_list_free(list);
            return -1;
        }

        /* Read the filename */
        if (fread(new_entry->filename, 1, filename_len_ul, file) != filename_len_ul)
        {
            DEBUG_PRINT("Failed to read filename from file (entry %lu)\n", i);
            free(new_entry);
            fclose(file);
            file_list_free(list);
            return -1;
        }
        // Ensure null termination, though filename_len_ul should include it.
        // If filename_len_ul was exactly FILE_LIST_MAX_FILENAME, strncpy in add would handle it.
        // Here, we assume fread got it right. Best to ensure filename_len_ul from file is sane.
        new_entry->filename[filename_len_ul - 1] = '\0'; // Ensure last char is null if len included it.
                                                         // Or, if len was pure string len, new_entry->filename[filename_len_ul] = '\0';
                                                         // Assuming filename_len_ul includes the null terminator.

        /* Read the rest of the entry data */
        if (fread(&new_entry->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fread(&new_entry->original_size, sizeof(unsigned long), 1, file) != 1 || // Replaced size_t with unsigned long
            fread(&new_entry->processed_size, sizeof(unsigned long), 1, file) != 1)
        { // Replaced size_t with unsigned long
            DEBUG_PRINT("Failed to read entry data from file (entry %lu)\n", i);
            free(new_entry);
            fclose(file);
            file_list_free(list);
            return -1;
        }

        /* Set next pointer to NULL */
        new_entry->next = NULL;

        /* Add to the end of the list (simplified, assumes file_list_add logic) */
        if (list->tail == NULL)
        {
            list->head = new_entry;
            list->tail = new_entry;
        }
        else
        {
            list->tail->next = new_entry;
            list->tail = new_entry;
        }
        list->count++;
    }

    fclose(file);

    DEBUG_PRINT("Loaded %lu entries from file '%s'\n", list->count, filename); // Use %lu

    return 0; // Success
}

void file_list_free(file_list_t *list)
{
    file_entry_t *current, *next_node; // Renamed 'next' to avoid conflict if list has a member named 'next'

    if (list == NULL)
    {
        return;
    }

    /* Free all entries */
    current = list->head;
    while (current != NULL)
    {
        next_node = current->next;
        free(current);
        current = next_node;
    }

    /* Reset list to initial state */
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1; // Reset sequence number too

    DEBUG_PRINT("Freed file list\n");
}

void file_list_print(file_list_t *list)
{
    file_entry_t *current;

    if (list == NULL)
    {
        printf("File list is NULL\n");
        return;
    }

    // Using %lu for unsigned long (list->count)
    printf("File list (%lu entries, next sequence #%lu):\n", list->count, list->next_sequence_num);

    if (list->count == 0)
    {
        printf("  (empty)\n");
        return;
    }

    current = list->head;
    while (current != NULL)
    {
        /* Print the entry */
        printf("--> %s\n", current->filename);
        // Using %lu for unsigned long types
        printf("    Sequence: #%lu\n", current->sequence_num);
        printf("    Original size: %lu bytes\n", current->original_size);
        printf("    Processed size: %lu bytes\n", current->processed_size);

        // Avoid division by zero for ratio
        if (current->original_size > 0)
        {
            printf("    Compression ratio: %.2f%%\n",
                   100.0 * (double)current->processed_size / (double)current->original_size);
        }
        else
        {
            printf("    Compression ratio: N/A (original size is 0)\n");
        }

        current = current->next;
    }
}
