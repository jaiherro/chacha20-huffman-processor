/*
 * batch.h - Batch file processing operations
 */

#ifndef BATCH_H
#define BATCH_H

#define MAX_BATCH_FILES 100         // Maximum files per batch
#define DEFAULT_OUTPUT_DIR "output" // Default output directory

int batch_process(char *filenames[], int num_files, const char *output_dir,
                  const char *password, int quiet);

#endif
