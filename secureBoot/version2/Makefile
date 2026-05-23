CC = gcc
CFLAGS = -Wall
LIBS = -lcrypto

TARGET = verifier

all: $(TARGET)

$(TARGET): verifier.c
	$(CC) $(CFLAGS) verifier.c -o $(TARGET) $(LIBS)

manifest:
	./generate_manifest.sh

clean:
	rm -f $(TARGET) secureBoot.boot
