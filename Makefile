# file Makefile
# author Lukas Pseja (xpsejal00)

CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -Werror
DFLAGS=-D_GNU_SOURCE
LDFLAGS=-lpcap

SRC_DIR=./src
BUILD_DIR=./build

TARGET=ipk-l4-scan

.PHONY: all run debug test clean

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/argparse.o $(BUILD_DIR)/network_utils.o $(BUILD_DIR)/scanner.o $(BUILD_DIR)/error.o
	$(CC) $(CFLAGS) -o $@ $^ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/argparse.o: $(SRC_DIR)/argparse.c $(SRC_DIR)/argparse.h $(SRC_DIR)/error.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/network_utils.o: $(SRC_DIR)/network_utils.c $(SRC_DIR)/network_utils.h $(SRC_DIR)/error.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/scanner.o: $(SRC_DIR)/scanner.c $(SRC_DIR)/scanner.h $(SRC_DIR)/error.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

$(BUILD_DIR)/error.o: $(SRC_DIR)/error.c $(SRC_DIR)/error.h $(SRC_DIR)/colors.h
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS) $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	@./test/argtest.sh

clean:
	rm -rf $(TARGET) $(BUILD_DIR)
