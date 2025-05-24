# Directories
SRC_DIR = src
INCLUDE_DIR = include
TEST_DIR = test
BUILD_DIR = build

# Compiler settings
CC ?= gcc
CFLAGS = -Wall -Werror -pedantic -std=c99 -I$(INCLUDE_DIR)

# Source files (Windows-compatible wildcards)
APP_SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)

# Object files in build directory
APP_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/$(SRC_DIR)/%.o,$(APP_SRCS))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/$(TEST_DIR)/%.o,$(TEST_SRCS))

# Library objects for tests (exclude main.o if it exists)
LIB_OBJS = $(filter-out $(BUILD_DIR)/$(SRC_DIR)/main.o, $(APP_OBJS))

# Executables in build directory
TARGET = $(BUILD_DIR)/secure_compress
TEST_TARGET = $(BUILD_DIR)/run_tests

# Default target
all: $(TARGET)

# Build main executable
$(TARGET): $(APP_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(APP_OBJS) -lm

# Build test executable  
$(TEST_TARGET): $(TEST_OBJS) $(LIB_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS) $(LIB_OBJS) -lm

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/$(SRC_DIR) $(BUILD_DIR)/$(TEST_DIR)
	@# Create subdirectories that might exist in src
	@for dir in $(sort $(dir $(APP_SRCS))); do \
		mkdir -p $(BUILD_DIR)/$$dir; \
	done

# Generic compilation rule for source files
$(BUILD_DIR)/$(SRC_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Test object files
$(BUILD_DIR)/$(TEST_DIR)/%.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Run tests
test: $(TEST_TARGET)
	$(TEST_TARGET)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all test clean