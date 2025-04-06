CC = g++
AS = as
CFLAGS = -std=c++11 -Wall -I./libAES  # Include directories
OPTS = -O0 -g

# Directories
SRC_DIRS = libAES main
ASSM_DIR = assm
OBJ_DIR = obj
BIN_DIR = bin

# Source and object files
SRCS = $(wildcard libAES/*.cpp main/*.cpp)
ASM_FILES = $(patsubst %.cpp, $(ASSM_DIR)/%.s, $(SRCS))
OBJS = $(patsubst %.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Executable name
EXEC = $(BIN_DIR)/main

# Create necessary directories
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR) $(ASSM_DIR))

# Step 1: Generate assembly files from C++ sources
$(ASSM_DIR)/%.s: %.cpp
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OPTS) -S $< -o $@
	@echo "Generated assembly for $<"

# Step 2: Assemble object files from assembly
$(OBJ_DIR)/%.o: $(ASSM_DIR)/%.s
	@mkdir -p $(dir $@)  # Ensure obj/ paths match source structure
	$(AS) $< -o $@
	@echo "Assembled object for $<"

# Step 3: Link object files to create the final executable
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $(OPTS) $(OBJS) -o $(EXEC)
	@echo "Linked object files to create the executable"
	@mkdir assm_files
	@cp -r $(ASSM_DIR)/* assm_files
	@rm -r $(ASSM_DIR)

# Default rule to build everything
all: $(EXEC)

# Clean (only remove the obj and bin directories, but leave assembly files)
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(ASSM_DIR) assm_files
	@echo "Cleaned up object and binary directories"