SRC_DIR   := srcs
INC_DIR   := incs
BUILD_DIR := objs

TARGET := chacha20

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

CC      := cc
CFLAGS  := -Wall -Wextra -std=c11 -I$(INC_DIR)
DEBUG_CFLAGS := $(CFLAGS) -g3

.PHONY: all debug clean fclean re

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(wildcard $(INC_DIR)/*.h) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

debug: CFLAGS := $(DEBUG_CFLAGS)
debug: clean all

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)

re: fclean all
