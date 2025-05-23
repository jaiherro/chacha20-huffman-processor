/**
 * ui.h - User interface and display utilities
 *
 * This header provides functions for displaying progress bars,
 * operation results, and other user interface elements.
 */

#ifndef UI_H
#define UI_H

/* Console formatting */
#define CLEAR_LINE "\r                                                                          \r"
#define PROGRESS_WIDTH 30

/**
 * Print binary data in hexadecimal format (debug mode only)
 */
#ifdef DEBUG
void print_hex(const char *label, const unsigned char *data, unsigned long len);
#else
#define print_hex(label, data, len) ((void)0)
#endif

/**
 * Print program usage instructions
 */
void print_usage(const char *program_name);

/**
 * Print a progress bar to show operation progress
 */
void print_progress_bar(unsigned long current, unsigned long total, unsigned long width);

/**
 * Print operation result with appropriate formatting
 */
void print_operation_result(int result, const char *operation);

/**
 * Print a summary of file processing operation
 */
void print_processing_summary(const char *operation, const char *input_file, const char *output_file,
                              unsigned long input_size, unsigned long output_size);

/**
 * Print a section header
 */
void print_section_header(const char *title);

#endif /* UI_H */
