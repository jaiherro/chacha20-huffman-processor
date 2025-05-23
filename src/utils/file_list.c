/**
 * file_list.c - File list management using linked lists
 */

#include "utils/file_list.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int file_list_init(file_list_t *list)
{
    if (!list)
        return -1;

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1;
    return 0;
}

int file_list_add(file_list_t *list, const char *input_filename, const char *output_filename,
                  unsigned long original_size, unsigned long processed_size)
{
    if (!list || !input_filename || !output_filename)
        return -1;

    file_entry_t *entry = malloc(sizeof(file_entry_t));
    if (!entry)
        return -1;

    strncpy(entry->input_filename, input_filename, FILE_LIST_MAX_FILENAME - 1);
    entry->input_filename[FILE_LIST_MAX_FILENAME - 1] = '\0';
    strncpy(entry->output_filename, output_filename, FILE_LIST_MAX_FILENAME - 1);
    entry->output_filename[FILE_LIST_MAX_FILENAME - 1] = '\0';
    entry->sequence_num = list->next_sequence_num++;
    entry->original_size = original_size;
    entry->processed_size = processed_size;
    entry->next = NULL;

    if (!list->tail)
    {
        list->head = list->tail = entry;
    }
    else
    {
        list->tail->next = entry;
        list->tail = entry;
    }

    list->count++;
    return 0;
}

file_entry_t *file_list_find(file_list_t *list, const char *filename)
{
    if (!list || !filename)
        return NULL;

    for (file_entry_t *current = list->head; current; current = current->next)
    {
        if (strstr(current->input_filename, filename) || strstr(current->output_filename, filename))
        {
            return current;
        }
    }
    return NULL;
}

unsigned long file_list_get_recent(file_list_t *list, unsigned long count, file_entry_t **result)
{
    if (!list || !result || !count)
        return 0;

    if (list->count <= count)
    {
        unsigned long i = 0;
        for (file_entry_t *current = list->head; current && i < list->count; current = current->next)
        {
            result[i++] = current;
        }
        return i;
    }

    // Initialize result array
    for (unsigned long i = 0; i < count; i++)
    {
        result[i] = NULL;
    }

    // Find most recent entries by sequence number
    for (file_entry_t *current = list->head; current; current = current->next)
    {
        for (unsigned long i = 0; i < count; i++)
        {
            if (!result[i] || current->sequence_num > result[i]->sequence_num)
            {
                // Shift entries down
                for (unsigned long j = count - 1; j > i; j--)
                {
                    result[j] = result[j - 1];
                }
                result[i] = current;
                break;
            }
        }
    }

    // Count non-NULL entries
    unsigned long result_count = 0;
    for (unsigned long i = 0; i < count && result[i]; i++)
    {
        result_count++;
    }

    return result_count;
}

int file_list_save(file_list_t *list, const char *filename)
{
    if (!list || !filename)
        return -1;

    FILE *file = fopen(filename, "wb");
    if (!file)
        return -1;

    // Write header
    if (fwrite(&list->count, sizeof(unsigned long), 1, file) != 1 ||
        fwrite(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1)
    {
        fclose(file);
        return -1;
    } // Write entries
    for (file_entry_t *current = list->head; current; current = current->next)
    {
        unsigned long input_filename_len = strlen(current->input_filename) + 1;
        unsigned long output_filename_len = strlen(current->output_filename) + 1;

        if (fwrite(&input_filename_len, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(current->input_filename, 1, input_filename_len, file) != input_filename_len ||
            fwrite(&output_filename_len, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(current->output_filename, 1, output_filename_len, file) != output_filename_len ||
            fwrite(&current->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(&current->original_size, sizeof(unsigned long), 1, file) != 1 ||
            fwrite(&current->processed_size, sizeof(unsigned long), 1, file) != 1)
        {
            fclose(file);
            return -1;
        }
    }

    fclose(file);
    return 0;
}

int file_list_load(file_list_t *list, const char *filename)
{
    if (!list || !filename)
        return -1;

    file_list_free(list);
    file_list_init(list);

    FILE *file = fopen(filename, "rb");
    if (!file)
        return 0; // Empty list is valid

    unsigned long count_from_file;
    if (fread(&count_from_file, sizeof(unsigned long), 1, file) != 1 ||
        fread(&list->next_sequence_num, sizeof(unsigned long), 1, file) != 1)
    {
        fclose(file);
        return 0; // Treat as empty file
    }
    for (unsigned long i = 0; i < count_from_file; i++)
    {
        unsigned long input_filename_len, output_filename_len;
        if (fread(&input_filename_len, sizeof(unsigned long), 1, file) != 1 ||
            input_filename_len == 0 || input_filename_len > FILE_LIST_MAX_FILENAME)
        {
            fclose(file);
            file_list_free(list);
            return -1;
        }

        file_entry_t *entry = malloc(sizeof(file_entry_t));
        if (!entry)
        {
            fclose(file);
            file_list_free(list);
            return -1;
        }

        if (fread(entry->input_filename, 1, input_filename_len, file) != input_filename_len ||
            fread(&output_filename_len, sizeof(unsigned long), 1, file) != 1 ||
            output_filename_len == 0 || output_filename_len > FILE_LIST_MAX_FILENAME ||
            fread(entry->output_filename, 1, output_filename_len, file) != output_filename_len ||
            fread(&entry->sequence_num, sizeof(unsigned long), 1, file) != 1 ||
            fread(&entry->original_size, sizeof(unsigned long), 1, file) != 1 ||
            fread(&entry->processed_size, sizeof(unsigned long), 1, file) != 1)
        {
            free(entry);
            fclose(file);
            file_list_free(list);
            return -1;
        }

        entry->input_filename[input_filename_len - 1] = '\0';
        entry->output_filename[output_filename_len - 1] = '\0';
        entry->next = NULL;

        if (!list->tail)
        {
            list->head = list->tail = entry;
        }
        else
        {
            list->tail->next = entry;
            list->tail = entry;
        }
        list->count++;
    }

    fclose(file);
    return 0;
}

void file_list_free(file_list_t *list)
{
    if (!list)
        return;

    file_entry_t *current = list->head;
    while (current)
    {
        file_entry_t *next = current->next;
        free(current);
        current = next;
    }

    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    list->next_sequence_num = 1;
}

void file_list_print(file_list_t *list)
{
    if (!list)
    {
        printf("File list is NULL\n");
        return;
    }

    printf("File list (%lu entries, next sequence #%lu):\n",
           list->count, list->next_sequence_num);

    if (list->count == 0)
    {
        printf("  (empty)\n");
        return;
    }
    for (file_entry_t *current = list->head; current; current = current->next)
    {
        printf("--> Input: %s\n", current->input_filename);
        printf("    Output: %s\n", current->output_filename);
        printf("    Sequence: #%lu\n", current->sequence_num);
        printf("    Original size: %lu bytes\n", current->original_size);
        printf("    Processed size: %lu bytes\n", current->processed_size);

        if (current->original_size > 0)
        {
            printf("    Compression ratio: %.2f%%\n",
                   100.0 * (double)current->processed_size / (double)current->original_size);
        }
        else
        {
            printf("    Compression ratio: N/A (original size is 0)\n");
        }
    }
}
