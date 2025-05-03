# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
TEST_DIR = test

# Compiler flags
CFLAGS = -Wall -Wextra -pedantic -std=c99 -I$(INCLUDE_DIR)
DEBUG_FLAGS = -DDEBUG -g

# Source files (automatically find all .c files)
ENCRYPTION_SRCS = $(wildcard $(SRC_DIR)/encryption/*.c)
COMPRESSION_SRCS = $(wildcard $(SRC_DIR)/compression/*.c)
SHARING_SRCS = $(wildcard $(SRC_DIR)/sharing/*.c)
UTILS_SRCS = $(wildcard $(SRC_DIR)/utils/*.c)
MAIN_SRC = $(SRC_DIR)/main.c

# Object files
ENCRYPTION_OBJS = $(ENCRYPTION_SRCS:.c=.o)
COMPRESSION_OBJS = $(COMPRESSION_SRCS:.c=.o)
SHARING_OBJS = $(SHARING_SRCS:.c=.o)
UTILS_OBJS = $(UTILS_SRCS:.c=.o)
MAIN_OBJ = $(MAIN_SRC:.c=.o)

# Target executable
TARGET = secure_compress

# Default target
all: $(TARGET)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

# Link the final executable
$(TARGET): $(ENCRYPTION_OBJS) $(COMPRESSION_OBJS) $(SHARING_OBJS) $(UTILS_OBJS) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ -lm

# Compile object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build files
clean:
	rm -f $(ENCRYPTION_OBJS) $(COMPRESSION_OBJS) $(SHARING_OBJS) $(UTILS_OBJS) $(MAIN_OBJ) $(TARGET)

# Test target
test: all
	$(CC) $(CFLAGS) -o tests $(TEST_DIR)/*.c $(ENCRYPTION_OBJS) $(COMPRESSION_OBJS) $(SHARING_OBJS) $(UTILS_OBJS) -lm
	./tests