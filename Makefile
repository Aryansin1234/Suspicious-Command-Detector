CC       = gcc
CFLAGS   = -D_GNU_SOURCE -Wall -Wextra -pedantic -std=c11 -O2
LDFLAGS  =
SRC_DIR  = src
INC_DIR  = include
BUILD_DIR= build

SRCS     = $(wildcard $(SRC_DIR)/*.c)
OBJS     = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
TARGET   = scd

.PHONY: all clean test docker-build docker-run docker-compose-up docker-compose-down

all: $(BUILD_DIR) $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(TARGET)

test:
	@bash tests/test_parser.sh
	@bash tests/test_rules.sh
	@bash tests/test_scoring.sh

docker-build:
	docker build -f docker/Dockerfile -t scd:latest .

docker-run:
	docker run --rm -v ~/.bash_history:/data/bash_history:ro scd:latest \
	  -f json /data/bash_history

docker-compose-up:
	docker compose -f docker/docker-compose.yml up --build

docker-compose-down:
	docker compose -f docker/docker-compose.yml down
