# Secure File Processor

A C implementation combining ChaCha20 encryption (RFC 8439) with Huffman compression for secure file processing.

## Features

- **ChaCha20 Encryption**: RFC 8439 compliant stream cipher implementation
- **Huffman Compression**: Lossless data compression using frequency-based encoding
- **Key Derivation**: Password-based key generation with salt and iterations  
- **File Tracking**: Linked list-based processing history
- **Batch Processing**: Multiple file operations with single password entry
- **Comprehensive Testing**: Includes RFC 8439 test vectors

## Build

```bash
make              # Build main executable
make test         # Build and run tests
make clean        # Clean build artifacts
```

## Usage

### Basic Operations
```bash
# Encrypt file
./secure_compress -e input.txt output.enc

# Decrypt file  
./secure_compress -d input.enc output.txt

# Compress file
./secure_compress -c input.txt output.huf

# Decompress file
./secure_compress -x input.huf output.txt
```

### Combined Operations
```bash
# Compress then encrypt
./secure_compress -p document.pdf document.secure

# Decrypt then decompress
./secure_compress -u document.secure document.pdf
```

### File Management
```bash
# List processed files
./secure_compress -l

# Find files by pattern
./secure_compress -f report
```

### Batch Processing
```bash
# Process multiple files
./secure_compress -b output_dir file1.txt file2.pdf file3.jpg

# Quiet mode (minimal output)
./secure_compress -p input.txt output.sec -q
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

## Implementation Details

### Encryption
- **Algorithm**: ChaCha20 with 256-bit keys and 96-bit nonces
- **Key Derivation**: Password + salt with 100,000 iterations
- **Salt**: 16-byte random salt per file

### Compression  
- **Algorithm**: Huffman coding with frequency analysis
- **Format**: Original size header + tree structure + compressed data
- **Efficiency**: Optimised for repetitive data patterns

### File Format
- **Encrypted**: `[16-byte salt][encrypted data]`
- **Compressed**: `[8-byte size][tree structure][compressed data]`
- **Processed**: Compressed format encrypted with salt prefix

## Project Structure

```
├── include/           # Header files
│   ├── compression/   # Huffman compression
│   ├── encryption/    # ChaCha20 and key derivation  
│   ├── operations/    # File and batch operations
│   └── utils/         # Utilities and UI
├── src/              # Source implementations
├── test/             # Test suites
└── makefile          # Build configuration
```

## Dependencies

- Standard C libraries only: `stdio.h`, `stdlib.h`, `string.h`, `math.h`
- C99 standard
- POSIX-compatible filesystem operations

## Testing

The test suite includes:
- RFC 8439 ChaCha20 test vectors
- Huffman compression/decompression validation
- Key derivation consistency checks
- File list operations testing

Run tests with `make test` to verify implementation correctness.

## Security Notes

- Passwords are cleared from memory after use
- Salt generation uses pseudo-random number generation
- Key derivation uses 100,000 iterations for resistance against brute force
- ChaCha20 implementation follows RFC 8439 specifications

## License

This project is provided as-is for educational and development purposes.