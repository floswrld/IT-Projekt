# Compiler and flags
CC = gcc
CFLAGS = -I../include/common -I../include/sphincs_utils -Wall -Wextra -O2

# Libraries
LIBS = -lssl -lcrypto -lcurl

# Source directories
COMMON_SRC = $(wildcard ../include/common/*.c)
SPHINCS_UTILS_SRC = $(wildcard ../include/sphincs_utils/*.c)

# Sources and targets
CLIENT_SRC = clientSphincs.c $(COMMON_SRC) $(SPHINCS_UTILS_SRC)
SERVER_SRC = serverSphincs.c $(COMMON_SRC) $(SPHINCS_UTILS_SRC)

CLIENT_TARGET = ClientSphincs
SERVER_TARGET = ServerSphincs

# Build rules
all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

