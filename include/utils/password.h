/*
 * password.h - Password handling utilities
 */

#ifndef PASSWORD_H
#define PASSWORD_H

#define MAX_PASSWORD 128

/* Prompt for password with optional confirmation */
int get_password(char *password, unsigned long max_len, int confirm);

#endif /* PASSWORD_H */
