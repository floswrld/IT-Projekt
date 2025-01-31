#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <microhttpd.h>
#include <openssl/sha.h>
#include <time.h>
#include "../include/kyber_utils/api.h"
#include "../include/kyber_utils/cJSON.h"

#define PORT 8080
#define MAX_POST_SIZE 8192

uint8_t global_secret_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t global_public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];

struct MHD_Response *create_response(const char *message) {
    return MHD_create_response_from_buffer(strlen(message), (void *)message, MHD_RESPMEM_PERSISTENT);
}

int aes_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    return ciphertext_len;
}

static int request_handler(void *cls, struct MHD_Connection *connection,
                           const char *url, const char *method,
                           const char *version, const char *upload_data,
                           size_t *upload_data_size, void **con_cls) {
    struct MHD_Response *response;
    int ret;
	printf("Running check");
    if (strcmp(url, "/get_public_key") == 0 && strcmp(method, "GET") == 0) {
      	printf("called get_public_key: %s\n", url);
        response = MHD_create_response_from_buffer(PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                   global_public_key, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    if (strcmp(url, "/send_encrypted_data") == 0 && strcmp(method, "POST") == 0) {
      printf("called send_encrypted_data: %s\n", url);
        if (*upload_data_size > 0) {
            cJSON *json = cJSON_Parse(upload_data);
            if (!json) {
                response = create_response("{\"error\": \"Invalid JSON\"}");
                ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            cJSON *ciphertext_json = cJSON_GetObjectItem(json, "ciphertext");
            cJSON *iv_json = cJSON_GetObjectItem(json, "iv");
            cJSON *encrypted_data_json = cJSON_GetObjectItem(json, "data");

            if (!cJSON_IsString(ciphertext_json) || !cJSON_IsString(iv_json) || !cJSON_IsString(encrypted_data_json)) {
                cJSON_Delete(json);
                response = create_response("{\"error\": \"Missing data\"}");
                ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                MHD_destroy_response(response);
                return ret;
            }

            uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
            unsigned char aes_key[32];
            unsigned char iv[16];
            unsigned char encrypted_data[4096];
            unsigned char decrypted_data[4096];

            memcpy(ciphertext, ciphertext_json->valuestring, PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES);
            memcpy(iv, iv_json->valuestring, 16);
            memcpy(encrypted_data, encrypted_data_json->valuestring, sizeof(encrypted_data));

            clock_t start_decap = clock();
            if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(shared_secret, ciphertext, global_secret_key) != 0) {
                response = create_response("{\"error\": \"Decapsulation failed\"}");
                ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
                MHD_destroy_response(response);
                cJSON_Delete(json);
                return ret;
            }
            clock_t end_decap = clock();

            SHA256(shared_secret, sizeof(shared_secret), aes_key);
            int decrypted_data_len = aes_decrypt(encrypted_data, sizeof(encrypted_data), aes_key, iv, decrypted_data);

            char response_msg[256];
            snprintf(response_msg, sizeof(response_msg), "{\"status\": \"Received\", \"decapsulation_time\": \"%f\", \"decrypted_data\": \"%.100s\"}",
                     (double)(end_decap - start_decap) / CLOCKS_PER_SEC, decrypted_data);

            response = create_response(response_msg);
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            cJSON_Delete(json);
            return ret;
        }
    }

    response = create_response("{\"error\": \"Not found\"}");
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
}

int main() {
    if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(global_public_key, global_secret_key) != 0) {
        fprintf(stderr, "Failed to generate Kyber key pair.\n");
        return 1;
    }

    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
                              &request_handler, NULL, MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }

    printf("Server running on port %d...\n", PORT);
    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}
