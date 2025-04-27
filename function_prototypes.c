//compression (ethan)
void compress_huffman(const char *input, char *output); // Compresses the input string using Huffman coding and stores the result in output.
void decompress_huffman(const char *input, char *output); // Decompresses the input string using Huffman coding and stores the result in output.

//encryption (jai)
void encrypt_xor(char *data, const char *key, int rounds); // Encrypts the data using XOR encryption with the given key and number of rounds.
void decrypt_xor(char *data, const char *key, int rounds); // Decrypts the data using XOR encryption with the given key and number of rounds.

//shamir's secret sharing (ethan & jai)
void generate_polynomial(int degree, int secret, int *coefficients, int prime); // Generates a polynomial of the given degree with the specified secret as the constant term and stores the coefficients in the array.
void evaluate_polynomial(const int *coefficients, int degree, int x, int prime); // Evaluates the polynomial at the given x value and returns the result modulo prime.
void generate_shares(int secret, int num_shares, int threshold, int prime, int shares[][2]); // Generates shares of the secret using Shamir's secret sharing scheme and stores them in the shares array.
void reconstruct_secret(int shares[][2], int threshold, int prime); // Reconstructs the secret from the given shares using Lagrange interpolation and returns the result modulo prime.

//utils (ethan & jai)
int modular_inverse(int a, int m); // Computes the modular inverse of a modulo m using the Extended Euclidean algorithm.
int modular_power(int base, int exp, int mod); // Computes base^exp modulo mod using the method of exponentiation by squaring.
int random_int(int min, int max); // Generates a random integer between min and max (inclusive).
