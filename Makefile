CC = gcc
CFLAGS = -O3 -Wall -Wextra -std=c11
TARGET = multicast_node
SOURCE = multicast_node.c

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

.PHONY: all clean
