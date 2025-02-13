CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -Werror
DFLAGS=-g
LDFLAGS=-lpcap

SRC_DIR=./src
BUILD_DIR=./build

TARGET=ipk-l4-scan

.PHONY: all run debug test clean

$(TARGET): $(BUILD_DIR)/main.o
	$(CC) $(CFLAGS) -o $@ $^ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

debug: DFLAGS+=-DDEBUG -g
debug: $(TARGET)

test: $(TARGET)
	@./test/argtest.sh

clean:
	rm -f $(TARGET) $(BUILD_DIR)/*.o

