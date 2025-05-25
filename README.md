# Secure File Processor

A C implementation combining ChaCha20 encryption (RFC 8439) with Huffman compression for secure file processing.

## Features

- **ChaCha20 Encryption**: RFC 8439 compliant stream cipher implementation
- **Huffman Compression**: Lossless data compression using frequency-based encoding
- **Key Derivation**: Password-based key generation with salt and iterations  
- **File Tracking**: Linked list-based processing history
- **Batch Processing**: Multiple file operations with single password entry
- **Comprehensive Testing**: Includes RFC 8439 test vectors
- **Debug Mode**: Comprehensive diagnostic output for troubleshooting

## Build

```bash
make              # Build main executable (./build/secure_compress)
make test         # Build and run tests (./build/run_tests)
make clean        # Clean build artifacts
```

The build system creates executables in the `build/` directory to keep the project root clean.

## Usage

### Basic Operations
```bash
# Encrypt file
./build/secure_compress -e input.txt output.enc

# Decrypt file  
./build/secure_compress -d input.enc output.txt

# Compress file
./build/secure_compress -c input.txt output.huf

# Decompress file
./build/secure_compress -x input.huf output.txt
```

### Combined Operations
```bash
# Compress then encrypt
./build/secure_compress -p document.pdf document.secure

# Decrypt then decompress
./build/secure_compress -u document.secure document.pdf
```

### File Management
```bash
# List processed files
./build/secure_compress -l

# Find files by pattern
./build/secure_compress -f report
```

### Batch Processing
```bash
# Process multiple files
./build/secure_compress -b output_dir file1.txt file2.pdf file3.jpg

# Quiet mode (minimal output)
./build/secure_compress -p input.txt output.sec -q

# Debug mode (verbose diagnostic output)
./build/secure_compress -e input.txt output.enc --debug
```

## Command Reference

| Mode | Arguments | Description |
|------|-----------|-------------|
| `-c` | `<input> <output>` | Compress file |
| `-x` | `<input> <output>` | Decompress file |
| `-e` | `<input> <output>` | Encrypt file |
| `-d` | `<input> <output>` | Decrypt file |
| `-p` | `<input> <output>` | Process (compress + encrypt) |
| `-u` | `<input> <output>` | Extract (decrypt + decompress) |
| `-l` | | List processed files |
| `-f` | `<pattern>` | Find files by pattern |
| `-b` | `<outdir> <files...>` | Batch process files |
| `-q` | | Quiet mode |
| `-h` | | Show help |
| `--debug` | | Enable debug mode |

## Implementation Details

### Encryption
- **Algorithm**: ChaCha20 with 256-bit keys and 96-bit nonces
- **Key Derivation**: Password + salt with 100,000 iterations
- **Salt**: 16-byte random salt per file
- **Validation**: Magic header for password verification

### Compression  
- **Algorithm**: Huffman coding with frequency analysis
- **Format**: Original size header + tree structure + compressed data
- **Streaming**: Two-pass streaming implementation for large files
- **Efficiency**: Optimised for repetitive data patterns

### File Formats
- **Encrypted**: `[16-byte salt][magic header][encrypted data]`
- **Compressed**: `[8-byte size][tree structure][compressed data]`
- **Processed**: Compressed format encrypted with salt prefix

## Project Structure

```
├── build/             # Build output directory (created by make)
├── include/           # Header files
│   ├── compression/   # Huffman compression
│   ├── encryption/    # ChaCha20 and key derivation  
│   ├── operations/    # File and batch operations
│   └── utils/         # Utilities and UI
├── src/               # Source implementations
│   ├── compression/   # Huffman implementation
│   ├── encryption/    # ChaCha20 and key derivation
│   ├── operations/    # File and batch operations
│   ├── utils/         # Utility implementations
│   └── main.c         # Main program entry point
├── test/              # Test suites
├── makefile           # Build configuration
└── README.md          # This file
```

## Dependencies

- **Standard C Libraries**: `stdio.h`, `stdlib.h`, `string.h`, `math.h`
- **C Standard**: C99 compliance required
- **System**: POSIX-compatible filesystem operations
- **Compiler**: GCC or compatible C compiler

## Testing

The comprehensive test suite includes:
- **ChaCha20**: RFC 8439 test vectors for encryption validation
- **Huffman**: Compression/decompression with various data types
- **Key Derivation**: Consistency and uniqueness checks
- **File List**: Linked list operations and persistence

```bash
# Run all tests
make test

# Individual test categories are run automatically
```

## Security Features

- **Memory Safety**: Passwords and keys are securely cleared after use
- **Salt Generation**: Pseudo-random salt generation for each file
- **Key Stretching**: 100,000 iterations for brute-force resistance
- **Standards Compliance**: ChaCha20 follows RFC 8439 specifications
- **Validation**: Magic headers verify correct decryption

## Error Handling

- **Input Validation**: Comprehensive parameter and file validation
- **Progress Tracking**: Visual progress bars for long operations
- **Debug Mode**: Detailed diagnostic output with `--debug` flag
- **File Safety**: Failed operations clean up partial output files

## File List Management

The program maintains a persistent history of processed files in `file_list.dat`:
- **Tracking**: Input/output file pairs with sizes and timestamps
- **Search**: Pattern-based file searching
- **Statistics**: Compression ratios and processing history

## License

This project is provided as-is for educational and development purposes.