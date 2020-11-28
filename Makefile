
# Target name
TARGET=run

# C files
SRC_DIR=src
SRC=$(wildcard $(SRC_DIR)/*.c)

# H files
INC_DIR=-Iinc/

# Objects
BUILD_DIR=build
OBJ=$(subst $(SRC_DIR), $(BUILD_DIR), $(SRC:%.c=%.o))

# Compiler settings
CC=gcc
C_FLAGS=-pedantic-errors -Wall -Wextra -Werror

# Libraries
LDFLAGS=-lcrypto -lpthread

.PHONY: all build clean debug

all: build $(OBJ)
	$(CC) $(C_FLAGS) -o $(BUILD_DIR)/$(TARGET) $(OBJ) $(LDFLAGS)

build:
	mkdir -p $(BUILD_DIR)

debug: C_FLAGS += -g
debug: all

$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) $(C_FLAGS) -c $< -o $@ $(INC_DIR)

clean:
	rm -rf $(BUILD_DIR)
