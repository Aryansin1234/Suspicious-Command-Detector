CC       = gcc
CFLAGS   = -Wall -Wextra -pedantic -std=c11 -O2
SRC_DIR  = src
INC_DIR  = include
BUILD_DIR= build

SRCS     = $(wildcard $(SRC_DIR)/*.c)
OBJS     = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TARGET   = scd

.PHONY: all clean run test

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

run: all
	./$(TARGET)

test: all
	@echo "=== Testing with sample malicious commands ==="
	@./$(TARGET) < tests/sample_malicious.txt || true
	@echo ""
	@echo "=== Testing with sample clean commands ==="
	@./$(TARGET) < tests/sample_clean.txt || true
