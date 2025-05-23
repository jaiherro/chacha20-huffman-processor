/**
 * batch.h - Batch file processing operations
 *
 * This header provides functions for processing multiple files
 * in batch mode.
 */

#ifndef BATCH_H
#define BATCH_H

#define MAX_BATCH_FILES 100         /* Maximum number of files in batch mode */
#define DEFAULT_OUTPUT_DIR "output" /* Default output directory for batch */

/**
 * Process multiple files in batch mode (Compress + Encrypt)
 *
 * @param filenames Array of input filenames
 * @param num_files Number of files to process
 * @param output_dir Output directory for processed files
 * @param password Password for encryption
 * @param quiet If non-zero, suppress output
 * @return 0 on success (all files processed), -1 if any files failed
 */
int batch_process(char *filenames[], int num_files, const char *output_dir,
                  const char *password, int quiet);

#endif /* BATCH_H */
