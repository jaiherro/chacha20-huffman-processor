# Directories
SRC_DIR = src
INCLUDE_DIR = include
TEST_DIR = test

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Werror -pedantic -std=c99 -I$(INCLUDE_DIR)

# Source files (Windows-compatible wildcards)
APP_SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)

# Object files
APP_OBJS = $(APP_SRCS:.c=.o)
TEST_OBJS = $(TEST_SRCS:.c=.o)

# Library objects for tests (exclude main.o if it exists)
LIB_OBJS = $(filter-out $(SRC_DIR)/main.o, $(APP_OBJS))

# Executables
TARGET = secure_compress
TEST_TARGET = run_tests

# Default target
all: $(TARGET)

# Build main executable
$(TARGET): $(APP_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm

# Build test executable  
$(TEST_TARGET): $(TEST_OBJS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm

# Generic compilation rule for all source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Test object files
$(TEST_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Run tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Clean build artifacts
clean:
	rm -f $(SRC_DIR)/*.o $(SRC_DIR)/*/*.o $(TEST_DIR)/*.o
	rm -f $(TARGET) $(TEST_TARGET) $(TARGET).exe $(TEST_TARGET).exe $(TEST_DIR)/test_list.dat

.PHONY: all test clean