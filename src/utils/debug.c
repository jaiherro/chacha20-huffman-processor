/**
 * debug.c - Debug utilities implementation
 *
 * Built by: Ethan Hall and Jai Herro
 *
 */

#include "utils/debug.h"
#include <stdio.h>
#include <string.h>

/* Global debug state */
int debug_enabled = 0;
int debug_level = DEBUG_LEVEL_INFO;

void debug_init(int enabled, int level)
{
    debug_enabled = enabled;
    debug_level = level;

    if (debug_enabled)
    {
        DEBUG_INFO("Debug mode initialised - level: %d", level);
    }
}

void debug_set_enabled(int enabled)
{
    debug_enabled = enabled;
    if (enabled)
    {
        DEBUG_INFO_MSG("Debug mode enabled");
    }
}

void debug_set_level(int level)
{
    if (level < DEBUG_LEVEL_NONE || level > DEBUG_LEVEL_TRACE)
    {
        level = DEBUG_LEVEL_INFO; /* Default to info level */
    }

    debug_level = level;
    DEBUG_INFO("Debug level set to: %d", level);
}

int debug_is_enabled(void)
{
    return debug_enabled;
}

int debug_get_level(void)
{
    return debug_level;
}

void debug_counter(char *buffer, size_t buffer_size)
{
    static unsigned long counter = 0;

    if (!buffer || buffer_size < 20)
    {
        return;
    }

    snprintf(buffer, buffer_size, "%08lu", ++counter);
}
