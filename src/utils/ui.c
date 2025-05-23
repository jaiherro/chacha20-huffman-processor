/**
 * ui.c - Implementation of user interface and display utilities
 */

#include "utils/ui.h"
#include <stdio.h>
#include <string.h>

void print_usage(const char *program_name)
{
    printf("Secure File Processor v1.0\n");
    printf("Professional file compression and encryption utility\n\n");

    printf("USAGE:\n");
    printf("  %s [MODE] [OPTIONS] [FILE(S)]\n\n", program_name);

    printf("MODES:\n");
    printf("  -c <input> <output>    Compress a file\n");
    printf("  -x <input> <output>    Decompress a file\n");
    printf("  -e <input> <output>    Encrypt a file (with password prompt)\n");
    printf("  -d <input> <output>    Decrypt a file (with password prompt)\n");
    printf("  -p <input> <output>    Process a file (compress then encrypt)\n");
    printf("  -u <input> <output>    Extract a file (decrypt then decompress)\n");
    printf("  -l                     List processed files (from file_list.dat)\n");
    printf("  -f <pattern>           Find files matching pattern in list\n");
    printf("  -b <outdir> <files..>  Batch process (compress+encrypt) multiple files\n");
    printf("  -h, --help             Show this help information\n\n");

    printf("OPTIONS:\n");
    printf("  -q                     Quiet mode (minimal output)\n\n");

    printf("EXAMPLES:\n");
    printf("  %s -e document.txt document.enc\n", program_name);
    printf("    Encrypt document.txt and save as document.enc\n\n");
    printf("  %s -d document.enc document.txt\n", program_name);
    printf("    Decrypt document.enc and save as document.txt\n\n");
    printf("  %s -p report.pdf report.secure\n", program_name);
    printf("    Compress and encrypt report.pdf\n\n");
    printf("  %s -u report.secure report.pdf\n", program_name);
    printf("    Decrypt and decompress report.secure\n\n");
    printf("  %s -b secure_files file1.txt file2.pdf file3.jpg\n", program_name);
    printf("    Batch process multiple files to secure_files directory\n\n");
    printf("  %s -l\n", program_name);
    printf("    List all previously processed files\n\n");

    printf("NOTE: Operations requiring encryption/decryption will prompt for a password.\n");
    printf("      Use strong passwords for optimal security.\n");
}

void print_progress_bar(unsigned long current, unsigned long total, unsigned long width)
{
    // Avoid division by zero if total is 0 (e.g., empty file)
    float percent = (total == 0) ? 1.0f : (float)current / total;
    // Ensure percent doesn't exceed 1.0
    if (percent > 1.0f)
        percent = 1.0f;

    unsigned long filled_width = (unsigned long)(width * percent);

    printf(CLEAR_LINE); // Clear the current line
    printf("Progress: [");

    /* Print filled portion */
    unsigned long i;
    for (i = 0; i < filled_width; i++)
    {
        printf("=");
    }

    /* Print cursor if not full */
    if (filled_width < width)
    {
        printf(">");
        i++;
    }

    /* Print empty portion */
    for (; i < width; i++)
    {
        printf(" ");
    }

    /* Print percentage */
    printf("] %5.1f%% (%lu/%lu bytes)", percent * 100.0f, current, total);
    fflush(stdout); // Ensure progress bar updates
}

void print_operation_result(int result, const char *operation)
{
    // Add newline before result for better spacing
    printf("\n");
    if (result == 0)
    {
        printf("RESULT: %s completed successfully.\n", operation);
    }
    else
    {
        // Use fprintf to stderr for errors
        fprintf(stderr, "ERROR: %s failed.\n", operation);
    }
}

void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              unsigned long input_size, unsigned long output_size)
{
    // Avoid division by zero for ratio calculation
    float ratio = (input_size == 0) ? 0.0f : (float)output_size * 100.0f / input_size;

    printf("\n");
    print_section_header("Processing Summary");
    printf("Operation: %s\n", operation);
    printf("Input file:  %s (%lu bytes)\n", input_file, input_size);
    printf("Output file: %s (%lu bytes)\n", output_file, output_size);

    // Only show ratio if input size is non-zero
    if (input_size > 0)
    {
        printf("Size ratio:  %.2f%%\n", ratio);
        // Only show savings if ratio is less than 100%
        if (ratio < 100.0f && ratio >= 0.0f)
        {
            printf("Space saved: %.2f%%\n", 100.0f - ratio);
        }
        else if (ratio > 100.0f)
        {
            printf("Size increase: %.2f%%\n", ratio - 100.0f);
        }
    }
    else
    {
        printf("Size ratio:  N/A (input size is 0)\n");
    }
}

void print_section_header(const char *title)
{
    printf("\n=== %s ===\n", title);
}
