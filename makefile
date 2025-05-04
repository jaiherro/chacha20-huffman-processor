# Directories
SRC_DIR = src
INCLUDE_DIR = include
TEST_DIR = test

# Compiler flags
# Ensure you use CFLAGS consistently, potentially separating debug flags
BASE_CFLAGS = -Wall -Wextra -pedantic -std=c99 -I$(INCLUDE_DIR)
# Use -Werror for submission builds if required:
# BASE_CFLAGS = -Wall -Werror -pedantic -std=c99 -I$(INCLUDE_DIR)
DEBUG_FLAGS = -DDEBUG -g
CFLAGS = $(BASE_CFLAGS) # Default to non-debug

# Source files (automatically find all .c files)
ENCRYPTION_SRCS = $(wildcard $(SRC_DIR)/encryption/*.c)
COMPRESSION_SRCS = $(wildcard $(SRC_DIR)/compression/*.c)
UTILS_SRCS = $(wildcard $(SRC_DIR)/utils/*.c)
MAIN_SRC = $(SRC_DIR)/main.c

# Object files
ENCRYPTION_OBJS = $(ENCRYPTION_SRCS:.c=.o)
COMPRESSION_OBJS = $(COMPRESSION_SRCS:.c=.o)
UTILS_OBJS = $(UTILS_SRCS:.c=.o)
MAIN_OBJ = $(MAIN_SRC:.c=.o)
ALL_OBJS = $(ENCRYPTION_OBJS) $(COMPRESSION_OBJS) $(UTILS_OBJS) $(MAIN_OBJ)
LIB_OBJS = $(ENCRYPTION_OBJS) $(COMPRESSION_OBJS) $(UTILS_OBJS) # Objects needed by tests

# Test source files
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c) # Find all .c files in test dir

# Target executables
TARGET = secure_compress
TEST_TARGET = run_tests

# Default target
all: $(TARGET)

# Debug build setup
debug: CFLAGS += $(DEBUG_FLAGS) -DCHACHA20_DEBUG -DKDF_DEBUG -DHUFFMAN_DEBUG -DFILE_LIST_DEBUG # Enable debug prints in modules
debug: $(TARGET)

# Link the main executable
$(TARGET): $(ALL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm

# Compile object files (using CFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(SRC_DIR)/*/*.o $(SRC_DIR)/*.o $(TEST_DIR)/*.o $(TARGET) $(TEST_TARGET) $(TEST_DIR)/test_list.dat

# Phony target for test execution
.PHONY: test

# Test target: build and run the tests
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Link the test executable
# Note: Links test sources and library object files, but not main.o
$(TEST_TARGET): $(TEST_SRCS) $(LIB_OBJS) $(TEST_DIR)/test_utils.h
	$(CC) $(BASE_CFLAGS) $(DEBUG_FLAGS) -DCHACHA20_DEBUG -DKDF_DEBUG -DHUFFMAN_DEBUG -DFILE_LIST_DEBUG -o $@ $(TEST_SRCS) $(LIB_OBJS) -lm # Compile tests with debug flags always on for better diagnostics