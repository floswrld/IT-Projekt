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
#include "../include/kyber_utils/api.h"

#define ITERATIONS 1
#define URL "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
#define CSV_FILE "client_timings.csv"
#define LOG_FILE "client_log.txt"
#define BUFFER_SIZE 256

#define UNUSED(x) (void)(x)

char API_BASE_URL[256] = "http://";
static const char encoding_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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
        fprintf(stderr, "curl_easy_perform() send_get_request failed: %s\n", curl_easy_strerror(res));
    }

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

    // Initialisierung mit AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Fehler: EVP_EncryptInit_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Verschlüsselung der Daten
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len)) {
        fprintf(stderr, "Fehler: EVP_EncryptUpdate() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalisieren der Verschlüsselung (Padding hinzufügen)
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
    int output_length = 4 * ((length + 2) / 3);
    // Speicher für das Ergebnis plus den Nullterminator allokieren
    unsigned char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) {
        return NULL; // Speicherallokierung fehlgeschlagen
    }
    int i, j;
    for (i = 0, j = 0; i < length;) {
        // Hole bis zu 3 Bytes aus dem Input. Falls weniger als 3 Bytes übrig sind, wird 0 verwendet.
        uint32_t octet_a = i < length ? input[i++] : 0;
        uint32_t octet_b = i < length ? input[i++] : 0;
        uint32_t octet_c = i < length ? input[i++] : 0;
        // Kombiniere die drei Bytes zu einem 24-Bit-Wert
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        // Zerlege den 24-Bit-Wert in vier 6-Bit-Werte und wandle diese in Base64-Zeichen um
        encoded_data[j++] = encoding_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 6)  & 0x3F];
        encoded_data[j++] = encoding_table[triple         & 0x3F];
    }
    // Bei unvollständigen 3-Byte-Blöcken wird mit '=' gepolstert
    int mod = length % 3;
    if (mod > 0) {
        encoded_data[output_length - 1] = '=';
        if (mod == 1) {
            encoded_data[output_length - 2] = '=';
        }
    }
    // Nullterminierung des Strings
    encoded_data[output_length] = '\0';
    return encoded_data;
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

    // Get Data to encrypt
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
    printf("Heruntergeladene JSON-Daten:\n%s\n", chunk.memory);
    curl_easy_cleanup(curl_handle);

    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");

    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }

    fprintf(csv_file, "Iteration,Encapsulation Time (microseconds),AES256 Encryption Time (microseconds)\n");

    for (int i = 0; i < ITERATIONS; i++) {
      // 1. Public Key Request
        struct MemoryStruct response;
        struct timespec start_encap, end_encap, start_encrypt, end_encrypt;
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/init");
        send_post_request(buffer, "", &response);
        free(response.memory);
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/get_public_key");
        send_get_request(buffer, &response);
        if (response.size == 0) {
            fprintf(log_file, "Failed to retrieve public key (iteration %d).\n", i + 1);
            free(response.memory);
            continue;
        }
        uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
        memcpy(public_key, response.memory, PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
        free(response.memory);


        // 2. Kyber Encapsulation
        uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];

        clock_gettime(CLOCK_MONOTONIC_RAW, &start_encap);
        PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_encap);
        uint64_t encap_time = (end_encap.tv_sec - start_encap.tv_sec) * 1000000 + (end_encap.tv_nsec - start_encap.tv_nsec) / 1000;

        // 3. AES Key ableiten
        unsigned char aes_key[32];
        SHA256(shared_secret, sizeof(shared_secret), aes_key);
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));

        // 4. Daten verschlüsseln (Placeholder)
        unsigned char encrypted_data[4096];
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_encrypt);
        int encrypted_data_len = aes_encrypt(chunk.memory, chunk.size, aes_key, iv, encrypted_data);
        UNUSED(encrypted_data_len);
        printf("Encrypted data (Hex):\n");
        for (int i = 0; i < encrypted_data_len; i++) {
            printf("%02x ", encrypted_data[i]);
        }
        printf("\n");
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_encrypt);
        uint64_t encrypt_time = (end_encrypt.tv_sec - start_encrypt.tv_sec) * 1000000 + (end_encrypt.tv_nsec - start_encrypt.tv_nsec) / 1000;

        fprintf(csv_file, "%d,%lu,%lu\n", i + 1, encap_time, encrypt_time);

        unsigned char *ba64_ciphertext = base64_encode(ciphertext, sizeof(ciphertext));
        unsigned char *ba64_iv = base64_encode(iv, sizeof(iv));
        unsigned char *ba64_encrypted_data = base64_encode(encrypted_data, sizeof(encrypted_data));

        // 6. Send ciphertext and encrypted data to server
        char post_data[8192];
        sprintf(post_data, "{ \"ciphertext\": \"%s\", \"iv\": \"%s\", \"data\": \"%s\" }", ba64_ciphertext, ba64_iv, ba64_encrypted_data);
        printf("Post Data: \n%s\n", post_data);

        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/send_encrypted_data");
        send_post_request(buffer, post_data, &response);
        fprintf(log_file, "Server response (iteration %d): %s\n", i + 1, response.memory);
        printf("Server response (iteration %d): %s\n", i + 1, response.memory);

        // Speicher freigeben
        free(response.memory);
    }
    fclose(csv_file);
    fclose(log_file);
    return 0;
}