# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build main executable (creates ./build/secure_compress)
make

# Build and run comprehensive test suite
make test

# Clean all build artifacts
make clean
```

The build system uses GCC with C99 standard and creates all outputs in the `build/` directory to keep the project root clean.

## Architecture Overview

This is a secure file processor implementing ChaCha20 encryption (RFC 8439 compliant) with Huffman compression. The codebase is structured into distinct functional modules:

### Core Components

- **Encryption Module** (`src/encryption/`, `include/encryption/`): ChaCha20 stream cipher implementation with password-based key derivation using 100,000 iterations and 16-byte random salts
- **Compression Module** (`src/compression/`, `include/compression/`): Huffman coding with frequency analysis and two-pass streaming for large files
- **Operations Module** (`src/operations/`, `include/operations/`): High-level file operations (encrypt, decrypt, compress, decompress) and batch processing
- **Utils Module** (`src/utils/`, `include/utils/`): Password handling, file system operations, UI components, and debug utilities

### Operation Modes

The main program (`src/main.c`) supports multiple operation modes:
- Single file operations: `-c` (compress), `-x` (decompress), `-e` (encrypt), `-d` (decrypt)
- Combined operations: `-p` (process = compress + encrypt), `-u` (extract = decrypt + decompress)  
- File management: `-l` (list processed files), `-f` (find files by pattern)
- Batch processing: `-b` (process multiple files with single password)

### File Formats

- **Encrypted files**: `[16-byte salt][magic header][encrypted data]`
- **Compressed files**: `[8-byte size][tree structure][compressed data]`
- **Processed files**: Compressed format encrypted with salt prefix

### Testing Framework

The test suite (`test/`) uses custom assertion macros defined in `test_utils.h`:
- `ASSERT_TRUE(condition, msg)` - Boolean assertions
- `ASSERT_EQUAL(a, b, msg)` - Equality assertions  
- `ASSERT_MEM_EQUAL(a, b, len, msg)` - Memory comparison assertions

Test categories include ChaCha20 RFC 8439 test vectors, Huffman compression validation, key derivation consistency, file list operations, and integration tests.

### Security Features

- Password and key material is securely cleared from memory after use
- Random salt generation for each encrypted file
- Magic headers for password verification during decryption
- Input validation and error handling throughout

### Debug System

Comprehensive debug logging is available via `--debug` flag, implemented in `src/utils/debug.c` with function entry/exit tracing and hierarchical log levels.