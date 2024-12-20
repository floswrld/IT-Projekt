# Compiler and flags
CC = gcc
CFLAGS = -I../include/common -I../include/kyber_utils -Wall -Wextra -O2

# Libraries
LIBS = -lssl -lcrypto -lcurl

# Source directories
COMMON_SRC = $(wildcard ../include/common/*.c)
KYBER_UTILS_SRC = $(wildcard ../include/kyber_utils/*.c)

# Sources and targets
CLIENT_SRC = client.c $(COMMON_SRC) $(KYBER_UTILS_SRC)
SERVER_SRC = server.c $(COMMON_SRC) $(KYBER_UTILS_SRC)

CLIENT_TARGET = ClientKyber
SERVER_TARGET = ServerKyber

# Build rules
all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

