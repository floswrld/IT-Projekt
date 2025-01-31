#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>
#include "../include/kyber_utils/api.h"

#define ITERATIONS 1000
#define CSV_FILE "client_timings.csv"
#define LOG_FILE "client_log.txt"
#define BUFFER_SIZE 256

char API_BASE_URL[256] = "http://";

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

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

void send_get_request(const char *url, struct MemoryStruct *response) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return;
    }

    response->memory = malloc(1);  // initial allocation
    response->size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

int aes_encrypt(unsigned char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    return plaintext_len;
}

int main() {
    char input[64];
    char buffer[BUFFER_SIZE];
    int a, b, c, d, port;
    int valid = 0;

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

    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");

    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Encapsulation Time (seconds)\n");

    for (int i = 0; i < ITERATIONS; i++) {
        struct MemoryStruct response;
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/get_public_key");
        printf("%s\n", buffer);
        send_get_request(buffer, "", &response);

        if (response.size == 0) {
            fprintf(log_file, "Failed to retrieve public key (iteration %d).\n", i + 1);
            free(response.memory);
            continue;
        }

        uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
        printf("%s\n", response.memory);
        memcpy(public_key, response.memory, PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
        free(response.memory);

        // 2. Kyber Encapsulation
        uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];

        clock_t start_encap = clock();
        PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
        clock_t end_encap = clock();

        double encap_time = (double)(end_encap - start_encap) / CLOCKS_PER_SEC;
        fprintf(csv_file, "%d,%f\n", i + 1, encap_time);

        // 3. AES Key ableiten
        unsigned char aes_key[32];
        SHA256(shared_secret, sizeof(shared_secret), aes_key);
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));

        // 4. Daten verschlüsseln (Placeholder)
        unsigned char encrypted_data[4096];
        int encrypted_data_len = aes_encrypt(response.memory, response.size, aes_key, iv, encrypted_data);

        // 5. Send ciphertext and encrypted data to server
        char post_data[8192];
        sprintf(post_data, "{ \"ciphertext\": \"%s\", \"iv\": \"%s\", \"data\": \"%s\" }",
                ciphertext, iv, encrypted_data);

        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/send_encrypted_data");
        printf("%s", buffer);
        send_post_request(buffer, post_data, &response);
        fprintf(log_file, "Server response (iteration %d): %s\n", i + 1, response.memory);
        free(response.memory);
    }

    fclose(csv_file);
    fclose(log_file);
    return 0;
}
