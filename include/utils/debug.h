/*
 * debug.h - Debug utilities and macros
 */

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

/* Debug levels */
#define DEBUG_LEVEL_NONE 0
#define DEBUG_LEVEL_ERROR 1
#define DEBUG_LEVEL_WARN 2
#define DEBUG_LEVEL_INFO 3
#define DEBUG_LEVEL_TRACE 4

/* Global debug state */
extern int debug_enabled;
extern int debug_level;

/* Debug initialisation and control */
void debug_init(int enabled, int level);
void debug_set_enabled(int enabled);
void debug_set_level(int level);
int debug_is_enabled(void);
int debug_get_level(void);

/* Helper function to get current debug counter */
void debug_counter(char *buffer, size_t buffer_size);

/* Debug macros - separate versions for messages with and without arguments */
#define DEBUG_ERROR(fmt, ...)                                                  \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_ERROR)             \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    fprintf(stderr, "[%s ERROR] %s:%d: " fmt "\n", counter,    \
                            __FILE__, __LINE__, ##__VA_ARGS__);                \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_ERROR_MSG(msg)                                                   \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_ERROR)             \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    fprintf(stderr, "[%s ERROR] %s:%d: %s\n", counter,         \
                            __FILE__, __LINE__, msg);                          \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_WARN(fmt, ...)                                                   \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_WARN)              \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    fprintf(stderr, "[%s WARN ] %s:%d: " fmt "\n", counter,    \
                            __FILE__, __LINE__, ##__VA_ARGS__);                \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_WARN_MSG(msg)                                                    \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_WARN)              \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    fprintf(stderr, "[%s WARN ] %s:%d: %s\n", counter,         \
                            __FILE__, __LINE__, msg);                          \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_INFO(fmt, ...)                                                   \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_INFO)              \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    printf("[%s INFO ] %s:%d: " fmt "\n", counter, __FILE__,   \
                           __LINE__, ##__VA_ARGS__);                           \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_INFO_MSG(msg)                                                    \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_INFO)              \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    printf("[%s INFO ] %s:%d: %s\n", counter, __FILE__,        \
                           __LINE__, msg);                                     \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_TRACE(fmt, ...)                                                  \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_TRACE)             \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    printf("[%s TRACE] %s:%d: " fmt "\n", counter, __FILE__,   \
                           __LINE__, ##__VA_ARGS__);                           \
                }                                                              \
        }                                                                      \
    while (0)

#define DEBUG_TRACE_MSG(msg)                                                   \
    do                                                                         \
        {                                                                      \
            if (debug_enabled && debug_level >= DEBUG_LEVEL_TRACE)             \
                {                                                              \
                    char counter[32];                                          \
                    debug_counter(counter, sizeof(counter));                   \
                    printf("[%s TRACE] %s:%d: %s\n", counter, __FILE__,        \
                           __LINE__, msg);                                     \
                }                                                              \
        }                                                                      \
    while (0)

/* Function entry/exit tracing */
#define DEBUG_FUNCTION_ENTER(func_name)                                        \
    DEBUG_TRACE("Entering function: %s", func_name)

#define DEBUG_FUNCTION_EXIT(func_name, result)                                 \
    DEBUG_TRACE("Exiting function: %s with result: %d", func_name, result)

#define DEBUG_FUNCTION_EXIT_SIZE(func_name, result)                            \
    DEBUG_TRACE("Exiting function: %s with result: %lu", func_name, result)

/* Memory allocation debugging */
#define DEBUG_MALLOC(ptr, size)                                                \
    DEBUG_TRACE("malloc: allocated %zu bytes at %p", size, ptr)

#define DEBUG_FREE(ptr) DEBUG_TRACE("free: deallocating memory at %p", ptr)

/* File operation debugging */
#define DEBUG_FILE_OPEN(filename, mode)                                        \
    DEBUG_TRACE("fopen: opening file '%s' with mode '%s'", filename, mode)

#define DEBUG_FILE_CLOSE(filename)                                             \
    DEBUG_TRACE("fclose: closing file '%s'", filename)

/* Buffer operation debugging */
#define DEBUG_BUFFER_OP(op, size)                                              \
    DEBUG_TRACE("buffer operation: %s, size: %lu bytes", op, size)

/* Crypto operation debugging */
#define DEBUG_CRYPTO_OP(op, input_size, output_size)                           \
    DEBUG_TRACE("crypto operation: %s, input: %lu bytes, output: %lu bytes",   \
                op, input_size, output_size)

#endif
