# Secure File Processor - ChaCha20 Encryption and Huffman Compression

This C implementation provides a secure and efficient file processing solution that combines ChaCha20 encryption (RFC 8439) with Huffman compression. The program satisfies the project requirements, implementing both encryption and compression while using only the allowed libraries: stdio.h, stdlib.h, string.h, and math.h.

## Features

- **ChaCha20 Encryption and Decryption**: Implements the ChaCha20 stream cipher according to RFC 8439.
- **Huffman Compression and Decompression**: Efficiently compresses data by replacing sequences of identical bytes.
- **Secure Password-Based Key Derivation**: Uses a salt and multiple iterations to derive keys securely from passwords.
- **File Management**: Maintains a list of processed files using a linked list data structure.
- **Multiple Operation Modes**: Supports encryption, decryption, compression, decompression and combinations.
- **Batch Processing**: Process multiple files at once in quiet mode.
- **Comprehensive Testing**: Includes test vectors from RFC 8439 to verify correctness.
- **Debug Mode**: Optional verbose debugging information at compile-time.

## Compilation

To compile the program, use the provided makefile:

```bash
# Standard build
make

# Debug build with verbose output
make debug

# Run tests
make test

# Clean build files
make clean
```

## Usage

The program supports various operation modes:

```
# Run a demonstration
./secure_processor

# Encrypt a file (will prompt for password)
./secure_processor -e infile outfile

# Decrypt a file (will prompt for password)
./secure_processor -d infile outfile

# Compress a file
./secure_processor -c infile outfile

# Decompress a file
./secure_processor -x infile outfile

# Process a file (encrypt+compress)
./secure_processor -p infile outfile

# Extract a file (decompress+decrypt)
./secure_processor -u infile outfile

# Run built-in tests
./secure_processor -t

# List processed files
./secure_processor -l

# Find a file in the list
./secure_processor -f filename

# Batch process multiple files
./secure_processor -b output_dir file1 file2 file3
```

Additional options:
- `-i iterations` - Specify the number of iterations for key derivation (default: 10000)
- `-q` - Quiet mode (minimal output)

## Project Structure

```
├── include/               # Header files
│   ├── compression/       # Compression algorithms
│   ├── encryption/        # Encryption algorithms
│   └── utils/             # Utility functions
├── src/                   # Source files
│   ├── compression/       # Compression implementations
│   ├── encryption/        # Encryption implementations
│   ├── utils/             # Utility implementations
│   └── main.c             # Main program entry point
├── test/                  # Test files
│   ├── test_compression.c # Huffman tests
│   └── test_encryption.c  # ChaCha20 tests
├── makefile               # Build configuration
└── README.md              # This file
```