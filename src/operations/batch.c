/**
 * batch.c - Batch processing operations
 */

#include "operations/batch.h"
#include "operations/file_operations.h"
#include "utils/ui.h"
#include "utils/filesystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int batch_process(char *input_files[], int num_files, const char *output_dir,
                  const char *password, int quiet)
{
    int success_count = 0;
    int failure_count = 0;
    char output_path[MAX_FILENAME];
    char *filename_only;
    unsigned long original_size, processed_size;

    if (!quiet)
    {
        print_section_header("Batch Processing");
        printf("Processing %d files to directory: %s\n", num_files, output_dir);
        printf("Operation: Compress and Encrypt\n\n");
    }

    for (int i = 0; i < num_files; i++)
    {
        if (!file_exists(input_files[i]))
        {
            if (!quiet)
            {
                fprintf(stderr, "WARNING: Input file '%s' does not exist or cannot be read. Skipping.\n",
                        input_files[i]);
            }
            failure_count++;
            continue;
        }

        // Extract filename from path
        filename_only = strrchr(input_files[i], '/');
        if (filename_only == NULL)
        {
            filename_only = strrchr(input_files[i], '\\');
        }
        if (filename_only != NULL)
        {
            filename_only++; // Skip the separator
        }
        else
        {
            filename_only = input_files[i]; // No path separator found
        }

        // Create output filename
        snprintf(output_path, sizeof(output_path), "%s/%s.secure", output_dir, filename_only);
        output_path[sizeof(output_path) - 1] = '\0';

        if (!quiet)
        {
            printf("Processing file %d of %d: %s\n", i + 1, num_files, input_files[i]);
        }

        processed_size = process_file(input_files[i], output_path, password, quiet, &original_size);

        if (processed_size > 0)
        {
            success_count++;
            if (!quiet)
            {
                printf("SUCCESS: Processed %s -> %s\n", input_files[i], output_path);
            }
            // Add to file list
            if (add_entry_to_file_list(input_files[i], output_path, original_size, processed_size, quiet) != 0)
            {
                if (!quiet)
                {
                    fprintf(stderr, "WARNING: Failed to add '%s -> %s' to file list.\n", input_files[i], output_path);
                }
            }
        }
        else
        {
            failure_count++;
            if (!quiet)
            {
                fprintf(stderr, "FAILED: Unable to process %s\n", input_files[i]);
            }
        }

        if (!quiet && i < num_files - 1)
        {
            printf("\n");
        }
    }

    if (!quiet)
    {
        printf("\n");
        print_section_header("Batch Processing Summary");
        printf("Total files: %d\n", num_files);
        printf("Successful: %d\n", success_count);
        printf("Failed: %d\n", failure_count);

        if (failure_count == 0)
        {
            print_operation_result(0, "Batch processing");
        }
        else
        {
            print_operation_result(1, "Batch processing (some operations failed)");
        }
    }

    return (failure_count == 0) ? 0 : 1;
}
