#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include "../include/sphincs_utils/api.h"
#include "../include/kyber_utils/cJSON.h"

/* ---------------- DEFINITIONS ---------------- */
#define SHA256_DIGEST_LENGTH 32 // Define SHA-256 hash length
#define NUM_ITERATIONS 1000 // Define the number of iterations
#define CSV_FILE "sphincs.csv"
#define LOG_FILE "sphincs.txt"
#define URL "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
#define BUFFER_SIZE 256
#define UNUSED(x) (void)(x)
/* ---------------- DEFINITIONS ---------------- */

/* ---------------- GLOBAL VARIABLES ---------------- */
char API_BASE_URL[256] = "http://";
/* ---------------- GLOBAL VARIABLES ---------------- */

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + totalSize + 1);
    if (ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, totalSize);
    mem->size += totalSize;
    mem->memory[mem->size] = 0;
    return totalSize;
}

void send_post_request(const char *url, const char *post_data, struct MemoryStruct *response) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return;
    }

    response->memory = malloc(1);
    response->size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() in send_post_request failed: %s\n", curl_easy_strerror(res));
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}


int aes_encrypt(char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Fehler: EVP_CIPHER_CTX_new() schlug fehl.\n");
        return -1;
    }
    int len;
    int ciphertext_len = 0;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Fehler: EVP_EncryptInit_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len)) {
        fprintf(stderr, "Fehler: EVP_EncryptUpdate() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Fehler: EVP_EncryptFinal_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

unsigned char *base64_encode(const unsigned char *input, int length) {
    int encoded_length = 4 * ((length + 2) / 3);
    unsigned char *encoded = malloc(encoded_length + 1);
    if (encoded == NULL) {
        fprintf(stderr, "Fehler: malloc in base64_encode() schlug fehl.\n");
        return NULL;
    }
    int actual_length = EVP_EncodeBlock(encoded, input, length);
    if (actual_length < 0) {
        fprintf(stderr, "Fehler: EVP_EncodeBlock schlug fehl.\n");
        free(encoded);
        return NULL;
    }
    encoded[actual_length] = '\0';
    return encoded;
}

int main() {
    /* -------- Init files -------- */
    char input[64];
    char buffer[BUFFER_SIZE];
    int a, b, c, d, port;
    int valid = 0;
    /* -------- Init files -------- */

    /* -------- Dialog to determine <ip-address>:<port> to connect to -------- */
    while (!valid) {
        printf("Bitte geben Sie die Adresse im Format <IP:Port> ein (z.B. 127.0.0.1:8080): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            continue;
        }
        input[strcspn(input, "\n")] = '\0';
        if (sscanf(input, "%d.%d.%d.%d:%d", &a, &b, &c, &d, &port) == 5) {
            if (a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
                c >= 0 && c <= 255 && d >= 0 && d <= 255 && port > 0 && port <= 65535) {
                valid = 1;
                }
        }
        if (!valid) {
            printf("Eingabe ist nicht korrekt formatiert. Bitte versuchen Sie es erneut.\n");
        }
    }
    strcat(API_BASE_URL, input);
    /* -------- Dialog to determine <ip-address>:<port> to connect to -------- */

    /* -------- Get Data to encrypt via AES256 -------- */
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, URL);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    res = curl_easy_perform(curl_handle);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return 1;
    }
    curl_easy_cleanup(curl_handle);
    /* -------- Get Data to encrypt via AES256 -------- */

    /* -------- Init files -------- */
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");
    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }
    fprintf(csv_file, "Iteration,Encapsulation Time (microseconds),AES256 Encryption Time (microseconds)\n");
    /* -------- Init files -------- */

    /* -------- Init POST Request -------- */
    struct MemoryStruct responseInit;
    snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/init");
    send_post_request(buffer, "", &responseInit);
    free(responseInit.memory);
    /* -------- Init POST Request -------- */

    /* -------- Iterations -------- */
    for (int i = 0; i < ITERATIONS; i++) {

        /* ---- AES Key Generation ---- */
        uint8_t public_key[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES];
        uint8_t secret_key[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_SECRETKEYBYTES];
        uint8_t signature[PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES];
        size_t signature_len;
        unsigned char key[32]; // 256-bit key
        unsigned char iv[16]; // 128-bit IV
        memset(key, 0x00, sizeof(key)); // Set key to all 0s (in real scenarios, use a secure key)
        memset(iv, 0x00, sizeof(iv)); // Set IV to all 0s
        /* ---- AES Key Generation ---- */

        /* ---- AES256 Encryption ---- */
        unsigned char encrypted_data[4096];
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_encrypt);
        int encrypted_data_len = aes_encrypt(chunk.memory, chunk.size, key, iv, encrypted_data);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_encrypt);
        uint64_t encrypt_time = (end_encrypt.tv_sec - start_encrypt.tv_sec) * 1000000 + (end_encrypt.tv_nsec - start_encrypt.tv_nsec) / 1000;
        /* ---- AES256 Encryption ---- */

        /* ---- Hash Encrypted Data ---- */
        unsigned char data_hash[SHA256_DIGEST_LENGTH];
        hash_data(encrypted_data, encrypted_data_len, data_hash);
        /* ---- Hash Encrypted Data ---- */

        /* ---- Keypair Generation ---- */
        if (PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(public_key, secret_key) != 0) {
            fprintf(log_file, "Key pair generation failed.\n");
            free(encrypted_data);
            return 1;
        }
        /* ---- Keypair Generation ---- */

        /* ---- Signature ---- */
        if (PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(signature, &signature_len,
            data_hash, SHA256_DIGEST_LENGTH, secret_key) != 0) {
            fprintf(log_file, "Signing failed.\n");
            free(encrypted_data);
            return 1;
        }
        /* ---- Signature ---- */

        /* ---- Print Meassured Times in csv ---- */
        fprintf(csv_file, "%d,%lu,%lu\n", i + 1, encap_time, encrypt_time);
        /* ---- Print Meassured Times in csv ---- */

        /* ---- Encode Base64 ---- */
        unsigned char *ba64_public_key = base64_encode(public_key, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES);
        unsigned char *ba64_signature = base64_encode(signature, signature_len);
        unsigned char *ba64_encrypted_data = base64_encode(encrypted_data, encrypted_data_len);
        /* ---- Encode Base64 ---- */

        /* ---- POST Request ---- */
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/send_encrypted_data");
        send_post_request(buffer, post_data, &response);
        fprintf(log_file, "Server response (iteration %d): %s\n", i + 1, response.memory);
        printf("Server response (iteration %d): %s\n", i + 1, response.memory);
        /* ---- POST Request ---- */

        /* ---- Build JSON to POST to Server ---- */
        char post_data[8192];
        sprintf(post_data, "{ \"public_key\": \"%s\", \"signature\": \"%s\", \"encrypted_data\": \"%s\" }", ba64_public_key, ba64_signature, ba64_encrypted_data);
        /* ---- Build JSON to POST to Server ---- */

        /* ---- Free memory ---- */
        free(response.memory);
        /* ---- Free memory ---- */
    }
    /* -------- Iterations -------- */

    /* -------- Close files -------- */
    fclose(csv_file);
    fclose(log_file);
    /* -------- Close files -------- */
    return 0;
}