# Compiler and flags
CC = gcc
CFLAGS = -I../include/common -I../include/kyber_utils -I../include/cJSON -I../include/libmicrohttpd-stf-m2 -Wall -Wextra -O2

# Libraries
LIBS = -lssl -lcrypto -lcurl -lmicrohttpd

# Source directories
COMMON_SRC = $(wildcard ../include/common/*.c)
KYBER_UTILS_SRC = $(wildcard ../include/kyber_utils/*.c)
CJSON_SRC = $(wildcard ../include/cJSON/*.c)

# Sources and targets
CLIENT_SRC = clientKyber.c $(COMMON_SRC) $(KYBER_UTILS_SRC)
SERVER_SRC = serverKyber.c $(COMMON_SRC) $(KYBER_UTILS_SRC) $(CJSON_SRC)

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

