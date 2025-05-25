/*
 * ui.h - User interface and display utilities
 */

#ifndef UI_H
#define UI_H

/* Console formatting constants */
#define CLEAR_LINE                                                             \
    "\r                                                                      " \
    "    \r"
#define PROGRESS_WIDTH 30

/* Print program usage instructions */
void print_usage (const char *program_name);

/* Display progress bar */
void print_progress_bar (unsigned long current, unsigned long total,
                         unsigned long width);

/* Print operation result */
void print_operation_result (int result, const char *operation);

/* Print file processing summary */
void print_processing_summary (const char *operation, const char *input_file,
                               const char *output_file,
                               unsigned long input_size,
                               unsigned long output_size);

/* Print section header */
void print_section_header (const char *title);

#endif
