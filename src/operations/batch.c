/**
 * batch.c - Implementation of batch file processing operations
 */

#include "operations/batch.h"
#include "operations/file_operations.h"
#include "utils/filesystem.h"
#include "utils/ui.h"
#include <stdio.h>
#include <string.h>

/* Debug printing support */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("[Batch] " fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

int batch_process(char *filenames[], int num_files, const char *output_dir_path,
                  const char *password, int iterations, int quiet)
{
    char output_file_path[MAX_FILENAME];
    char *current_filename_only;
    int overall_op_result = 0;
    int i, success_count = 0;
    unsigned long original_file_size, processed_file_size;

    if (!quiet)
    {
        print_section_header("Batch Processing (Compress + Encrypt)");
        printf("Files to process: %d\n", num_files);
        printf("Output directory: %s\n", output_dir_path);
        printf("Using %d iterations for key derivation\n", iterations);
    }

    if (ensure_directory_exists(output_dir_path) != 0)
    {
        // Error already printed by ensure_directory_exists
        return -1;
    }

    for (i = 0; i < num_files; i++)
    {
        current_filename_only = strrchr(filenames[i], '/');
        char *current_filename_only_bs = strrchr(filenames[i], '\\');
        if (current_filename_only_bs > current_filename_only)
        {
            current_filename_only = current_filename_only_bs;
        }
        current_filename_only = (current_filename_only == NULL) ? filenames[i] : current_filename_only + 1;

        if (*current_filename_only == '\0')
        {
            fprintf(stderr, "\n[%d/%d] Skipping invalid input filename: '%s'\n", i + 1, num_files, filenames[i]);
            overall_op_result = -1;
            continue;
        }

        snprintf(output_file_path, sizeof(output_file_path), "%s/%s.sec", output_dir_path, current_filename_only);
        output_file_path[sizeof(output_file_path) - 1] = '\0';

        if (!quiet)
        {
            printf("\n[%d/%d] Processing file:\n", i + 1, num_files);
            printf("    Input:  %s\n", filenames[i]);
            printf("    Output: %s\n", output_file_path);
        }

        if (!file_exists(filenames[i]))
        {
            fprintf(stderr, "    Status: Failed (Input file '%s' not found)\n", filenames[i]);
            overall_op_result = -1;
            continue;
        }

        processed_file_size = process_file(filenames[i], output_file_path, password, iterations, quiet, &original_file_size);
        if (processed_file_size > 0)
        {
            success_count++;
            if (add_entry_to_file_list(output_file_path, original_file_size, processed_file_size, quiet) != 0)
            {
                if (!quiet)
                {
                    fprintf(stderr, "    Warning: Failed to add '%s' to file list '%s'.\n", output_file_path, DEFAULT_FILE_LIST);
                }
            }
        }
        else
        {
            overall_op_result = -1;
        }
    }

    if (!quiet)
    {
        print_section_header("Batch Processing Summary");
        printf("Total files attempted: %d\n", num_files);
        printf("Successful:            %d\n", success_count);
        printf("Failed:                %d\n", num_files - success_count);
        if (overall_op_result == 0)
        {
            printf("\nAll files processed successfully!\n");
        }
        else
        {
            printf("\nSome files failed to process. Check the output above for details.\n");
        }
    }
    return overall_op_result;
}
