#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <microhttpd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>
#include <ctype.h>
#include "../include/sphincs_utils/api.h"
#include "../include/cJSON/cJSON.h"


/* ---------------- DEFINITIONS ---------------- */
#define PORT 8081
#define MAX_POST_SIZE 65536
#define SHA256_DIGEST_LENGTH 32 // Define SHA-256 hash length
#define UNUSED(x) (void)(x)
#define LOG_FILE "sphincs_server_log.txt"
/* ---------------- DEFINITIONS ---------------- */

/* ---------------- GLOBAL VARIABLES ---------------- */
uint8_t CSV_COUNTER = 0;
FILE *log_file;
/* ---------------- GLOBAL VARIABLES ---------------- */

struct MHD_Response *create_response(const char *message) {
    return MHD_create_response_from_buffer(strlen(message), (void *)message, MHD_RESPMEM_MUST_COPY);
}

struct connection_info_struct {
    char *data;
    size_t size;
};

unsigned char *base64_decode(const char *input, int *out_len) {
    int input_len = strlen(input);
    int max_decoded_length = (input_len * 3) / 4;
    unsigned char *decoded = malloc(max_decoded_length + 1); // +1 für den Nullterminator
    if (decoded == NULL) {
        fprintf(stderr, "Fehler: malloc in base64_decode() schlug fehl.\n");
        return NULL;
    }
    int decoded_length = EVP_DecodeBlock(decoded, (const unsigned char *)input, input_len);
    if (decoded_length < 0) {
        fprintf(stderr, "Fehler: EVP_DecodeBlock schlug fehl.\n");
        free(decoded);
        return NULL;
    }
    if (input_len > 0 && input[input_len - 1] == '=')
        decoded_length--;
    if (input_len > 1 && input[input_len - 2] == '=')
        decoded_length--;
    decoded[decoded_length] = '\0';
    if (out_len)
        *out_len = decoded_length;
    return decoded;
}

int aes_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Fehler: EVP_CIPHER_CTX_new() schlug fehl.\n");
        return -1;
    }
    int len;
    int plaintext_len = 0;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Fehler: EVP_DecryptInit_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Fehler: EVP_DecryptUpdate() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Fehler: EVP_DecryptFinal_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void hash_data(const unsigned char *data, size_t data_len, unsigned char *output_hash) {
    EVP_MD_CTX *mdctx;
    unsigned int hash_len;
    // Create and initialize the context
    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Failed to create hash context.\n");
        exit(EXIT_FAILURE);
    }
    // Initialize the hash function (SHA-256)
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "Failed to initialize hash function.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Update the hash with the data
    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "Failed to update hash with data.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Finalize the hash and retrieve the result
    if (1 != EVP_DigestFinal_ex(mdctx, output_hash, &hash_len)) {
        fprintf(stderr, "Failed to finalize hash.\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }
    // Free the context
    EVP_MD_CTX_free(mdctx);
}

/**
    Request Handler
    - handles HTTP Requests:
        - POST with Route: /init                   -    Sets CVS_COUNTER to zero
        - POST with Route: /send_encrypted_data    -    Gets JSON {"ciphertext":"test","iv":"123","data":"hereIsData"}
        - GET with Route: /get_public_key          -    Sends Public Key to requesting device
*/
static int request_handler(void *cls,
                           struct MHD_Connection *connection,
                           const char *url,
                           const char *method,
                           const char *version,
                           const char *upload_data,
                           size_t *upload_data_size,
                           void **con_cls) {
    UNUSED(cls);
    UNUSED(version);
    struct MHD_Response *response;
    int ret;

    /* ---------------------- Initialisierung von con_cls ---------------------- */
    if (*con_cls == NULL) {
        struct connection_info_struct *con_info = malloc(sizeof(struct connection_info_struct));
        if (con_info == NULL)
            return MHD_NO;
        con_info->data = malloc(1);
        if (con_info->data == NULL) {
            free(con_info);
            return MHD_NO;
        }
        con_info->data[0] = '\0';
        con_info->size = 0;
        *con_cls = (void *)con_info;
        return MHD_YES;
    }
    struct connection_info_struct *con_info = *con_cls;
    /* -------------------- Ende Initialisierung von con_cls -------------------- */

    /* -------------------- Init POST Method -------------------- */
    if (strcmp(url, "/init") == 0 && strcmp(method, "POST") == 0) {
        char response_msg[32];
        snprintf(response_msg, sizeof(response_msg), "CSV_COUNTER SET TO 0");
        printf("/init\n");
        response = create_response(response_msg);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        CSV_COUNTER = 0;
        return ret;
    }
    /* -------------------- Init POST Method -------------------- */


    /* -------------------- Send Encrypted Data POST Method -------------------- */
    if (strcmp(url, "/send_data_package") == 0 && strcmp(method, "POST") == 0) {

        /* -------- Load all POST Request Data -------- */
        printf("/send_data_package\n");
        if (*upload_data_size > 0) {
            size_t new_size = con_info->size + *upload_data_size;
            if (new_size > MAX_POST_SIZE) {
                response = create_response("{\"error\": \"POST data too large\"}");
                printf("Received to much data. MAX_POST_SIZE:%u bytes. Received: %zu bytes\n", MAX_POST_SIZE, new_size);
                ret = MHD_queue_response(connection, MHD_HTTP_CONTENT_TOO_LARGE, response);
                MHD_destroy_response(response);
                free(con_info->data);
                free(con_info);
                return ret;
            }
            char *new_data = realloc(con_info->data, new_size + 1);
            if (new_data == NULL)
                return MHD_NO;
            memcpy(new_data + con_info->size, upload_data, *upload_data_size);
            new_data[new_size] = '\0';
            con_info->data = new_data;
            con_info->size = new_size;
            fprintf(stderr, "DEBUG: Empfangener Chunk mit %zu Bytes\n", *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        }
        /* -------- Load all POST Request Data -------- */
        fprintf(stderr, "DEBUG: Gesamte Post Daten erhalten mit %zu Bytes\n", con_info->size);
        /* -------- Parse JSON with cJSON -------- */
        cJSON *json = cJSON_Parse(con_info->data);
        if (json == NULL) {
            fprintf(stderr, "DEBUG: cJSON_Parse Fehler: %s\n", cJSON_GetErrorPtr());
            response = create_response("{\"error\": \"Invalid JSON\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            *con_cls = NULL;
            return ret;
        }
        cJSON *public_key_json = cJSON_GetObjectItem(json, "public_key");
        cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
        cJSON *encrypted_data_json = cJSON_GetObjectItem(json, "encrypted_data");
        if (!cJSON_IsString(public_key_json) ||
                    !cJSON_IsString(signature_json) ||
                    !cJSON_IsString(encrypted_data_json)) {
            cJSON_Delete(json);
            response = create_response("{\"error\": \"Missing attribute\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            *con_cls = NULL;
            return ret;
        }
        /* -------- Parse JSON with cJSON -------- */

        /* -------- Decode Base64 -------- */
        int public_key_len = 0, signature_len = 0, encrypted_data_len = 0;
        unsigned char *decoded_public_key = base64_decode(public_key_json->valuestring, &public_key_len);
        unsigned char *decoded_signature = base64_decode(signature_json->valuestring, &signature_len);
        unsigned char *decoded_encrypted_data = base64_decode(encrypted_data_json->valuestring, &encrypted_data_len);
        if (!decoded_public_key ||
                    public_key_len != PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_PUBLICKEYBYTES ||
                    !decoded_signature || signature_len != PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_CRYPTO_BYTES ||
                    !decoded_encrypted_data) {
            cJSON_Delete(json);
            response = create_response("{\"error\": \"Oops! Something went wrong with base64_decode.\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            free(decoded_public_key);
            free(decoded_signature);
            free(decoded_encrypted_data);
            *con_cls = NULL;
            return ret;
        }
        /* -------- Decode Base64 -------- */

        /* ######## Sphincs Algorithm Start ######## */

        /* --- Init variables --- */
        struct timespec start_verification, end_verification;
        /* --- Init variables --- */

        /* --- Hash Data --- */
        unsigned char data_hash[SHA256_DIGEST_LENGTH];
        hash_data(decoded_encrypted_data, encrypted_data_len, data_hash);
        /* --- Hash Data --- */

        /* --- Verify the signature on the hash of the encrypted data --- */
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_verification);
        int verification_result = PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(decoded_signature,
        signature_len, data_hash, SHA256_DIGEST_LENGTH, decoded_public_key);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_verification);
        uint64_t verification_time = (end_verification.tv_sec - start_verification.tv_sec) * 1000000 + (end_verification.tv_nsec - start_verification.tv_nsec) / 1000;
        if (verification_result != 0) {
            fprintf(log_file, "Signature verification failed on iteration %d.\n", CSV_COUNTER + 1);
            free(decoded_signature);
            return 1;
        } else {
            fprintf(log_file, "Signature verification successful on iteration %d.\n", CSV_COUNTER + 1);
        }
        /* --- Verify the signature on the hash of the encrypted data --- */

        /* ######## Sphincs Algorithm End ######## */

        /* -------- Build and send HTTP Response -------- */
        char response_msg[16];
        snprintf(response_msg, sizeof(response_msg), "%ld", verification_time);
        response = create_response(response_msg);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        /* -------- Build and send HTTP Response -------- */

        /* -------- Free memory -------- */
        cJSON_Delete(json);
        free(con_info->data);
        free(con_info);
        free(decoded_public_key);
        free(decoded_signature);
        free(decoded_encrypted_data);
        *con_cls = NULL;
        return ret;
        /* -------- Free memory -------- */
    }
    /* -------------------- Send Encrypted Data POST Method -------------------- */

    /* -------------------- Standard: Unbekannte Route -------------------- */
    response = create_response("{\"error\": \"Not found\"}");
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
    /* -------------------- Standard: Unbekannte Route -------------------- */
}

int printIpAddress() {
    FILE *fp;
    char ip[64] = {0};
    fp = popen("ifconfig | grep 'inet ' | grep -m 1 -Po '192\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}'", "r");
    if (fp == NULL) {
        perror("popen failed");
        return EXIT_FAILURE;
    }
    if (fgets(ip, sizeof(ip), fp) != NULL)
        ip[strcspn(ip, "\n")] = '\0';
    else {
        fprintf(stderr, "Keine IP-Adresse gefunden.\n");
        pclose(fp);
        return EXIT_FAILURE;
    }
    pclose(fp);
    printf("Server is running on %s:%d\n", ip, PORT);
    return EXIT_SUCCESS;
}

int main() {
    /* -------- Init files -------- */
    log_file = fopen(LOG_FILE, "w");
    if (log_file == NULL) {
        printf("Unable to create log file.\n");
        return 1;
    }
    /* -------- Init files -------- */

    /* -------- Generate DAEMON -------- */
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
                              (MHD_AccessHandlerCallback)request_handler, NULL,
                              MHD_OPTION_END);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }
    /* -------- Generate DAEMON -------- */

    /* -------- Print IP Address -------- */
    printIpAddress();
    /* -------- Print IP Address -------- */

    /* -------- Stop condition -------- */
    char input[128];
    while (1) {
        printf("Geben Sie 'stop' ein, um den Server zu beenden:\n");
        if (fgets(input, sizeof(input), stdin) == NULL)
            break;
        input[strcspn(input, "\r\n")] = '\0';
        for (int i = 0; input[i]; i++)
            input[i] = tolower((unsigned char)input[i]);
        if (strcmp(input, "stop") == 0)
            break;
    }
    /* -------- Stop condition -------- */

    /* -------- End server -------- */
    MHD_stop_daemon(daemon);
    printf("Stopped Server\n");
    fclose(log_file);
    return 0;
    /* -------- End server -------- */
}