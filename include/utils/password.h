/**
 * password.h - Password handling utilities
 *
 * This header provides functions for secure password input
 * and handling.
 */

#ifndef PASSWORD_H
#define PASSWORD_H

#define MAX_PASSWORD 128 /* Maximum password length */

/**
 * Prompt for a password with optional confirmation
 *
 * @param password Buffer to store the password
 * @param max_len Maximum length of the password buffer
 * @param confirm If non-zero, prompt for password confirmation
 * @return 0 on success, -1 on failure
 */
int get_password(char *password, unsigned long max_len, int confirm);

#endif /* PASSWORD_H */
