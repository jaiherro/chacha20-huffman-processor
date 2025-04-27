//compression
void compress_huffman(const char *input, char *output);
void decompress_huffman(const char *input, char *output);

//encryption
void encrypt_xor(char *data, const char *key, int rounds);
void decrypt_xor(char *data, const char *key, int rounds);

//shamir's secret sharing
void generate_polynomial(int degree, int secret, int *coefficients, int prime);
void evaluate_polynomial(const int *coefficients, int degree, int x, int prime);
void generate_shares(int secret, int num_shares, int threshold, int prime, int shares[][2]);
void reconstruct_secret(int shares[][2], int threshold, int prime);

//utils
int modular_inverse(int a, int m);
int modular_power(int base, int exp, int mod);
int random_int(int min, int max);
