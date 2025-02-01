#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <microhttpd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>
#include <ctype.h>
#include "../include/kyber_utils/api.h"
#include "../include/kyber_utils/cJSON.h"

#define PORT 8080
#define MAX_POST_SIZE 8192
#define UNUSED(x) (void)(x)

/* Globale Kyber-Key-Paare */
uint8_t global_secret_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t global_public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];

/* Verbindungsspezifische Struktur zum Sammeln der POST-Daten */
struct connection_info_struct {
    char *post_data;
    size_t post_data_size;
    struct MHD_PostProcessor *postprocessor;
};

/* Erzeugt eine MHD-Antwort aus einem String */
struct MHD_Response *create_response(const char *message) {
    /* Hier verwenden wir MHD_RESPMEM_MUST_COPY, damit der String kopiert wird */
    return MHD_create_response_from_buffer(strlen(message), (void *)message, MHD_RESPMEM_MUST_COPY);
}

/* Base64-Codierung */
char *base64_encode(const unsigned char *input, int length) {
    int out_len = 4 * ((length + 2) / 3);
    char *encoded = malloc(out_len + 1);
    if (encoded == NULL) {
        return NULL;
    }
    int written = EVP_EncodeBlock((unsigned char *)encoded, input, length);
    if (written < 0) {
        free(encoded);
        return NULL;
    }
    encoded[written] = '\0';
    return encoded;
}

/* Base64-Decodierung */
unsigned char *base64_decode(const char *input, int *out_len) {
    int in_len = strlen(input);
    unsigned char *decoded = malloc(in_len);
    if (decoded == NULL) {
        return NULL;
    }
    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)input, in_len);
    if (decoded_len < 0) {
        free(decoded);
        return NULL;
    }
    *out_len = decoded_len;
    return decoded;
}

/* Dummy-AES-Entschlüsselungsfunktion (nur Platzhalter) */
int aes_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    UNUSED(ciphertext);
    UNUSED(ciphertext_len);
    UNUSED(key);
    UNUSED(iv);
    UNUSED(plaintext);
    return ciphertext_len;
}

/* Callback des Post-Prozessors: Wird für jedes empfangene POST-Datenstück aufgerufen */
static int iterate_post(void *coninfo_cls, enum MHD_ValueKind kind, const char *key,
                        const char *filename, const char *content_type, const char *transfer_encoding,
                        const char *data, uint64_t off, size_t size) {
    (void)kind;
    (void)key;
    (void)filename;
    (void)content_type;
    (void)transfer_encoding;
    (void)off;
    struct connection_info_struct *con_info = coninfo_cls;
    if (size > 0) {
        char *new_data = realloc(con_info->post_data, con_info->post_data_size + size + 1);
        if (!new_data)
            return MHD_NO;
        con_info->post_data = new_data;
        memcpy(con_info->post_data + con_info->post_data_size, data, size);
        con_info->post_data_size += size;
        con_info->post_data[con_info->post_data_size] = '\0';
    }
    return MHD_YES;
}

/* Callback, der nach Abschluss der Anfrage aufgerufen wird und die Verbindungsspezifischen Daten freigibt */
static void request_completed_callback(void *cls,
                                       struct MHD_Connection *connection,
                                       void **con_cls,
                                       enum MHD_RequestTerminationCode toe) {
    (void)cls;
    (void)connection;
    (void)toe;
    struct connection_info_struct *con_info = *con_cls;
    if (con_info) {
        if (con_info->postprocessor)
            MHD_destroy_post_processor(con_info->postprocessor);
        if (con_info->post_data)
            free(con_info->post_data);
        free(con_info);
    }
    *con_cls = NULL;
}

/* Request-Handler: Empfängt GET- und POST-Anfragen */
static int request_handler(void *cls,
                           struct MHD_Connection *connection,
                           const char *url,
                           const char *method,
                           const char *version,
                           const char *upload_data,
                           size_t *upload_data_size,
                           void **con_cls) {
    (void)cls;
    (void)version;

    /* Beim ersten Aufruf für diese Verbindung wird unsere Datenstruktur allokiert */
    if (NULL == *con_cls) {
        struct connection_info_struct *con_info = malloc(sizeof(struct connection_info_struct));
        if (!con_info)
            return MHD_NO;
        con_info->post_data = malloc(1);
        if (!con_info->post_data) {
            free(con_info);
            return MHD_NO;
        }
        con_info->post_data[0] = '\0';
        con_info->post_data_size = 0;
        con_info->postprocessor = NULL;
        if (strcmp(method, "POST") == 0) {
            con_info->postprocessor = MHD_create_post_processor(connection, MAX_POST_SIZE, iterate_post, (void *)con_info);
            if (!con_info->postprocessor) {
                free(con_info->post_data);
                free(con_info);
                return MHD_NO;
            }
        }
        *con_cls = (void *)con_info;
    }

    /* Verarbeitung von POST-Anfragen */
    if (strcmp(method, "POST") == 0) {
        struct connection_info_struct *con_info = *con_cls;
        if (*upload_data_size != 0) {
            /* Hier werden die eingehenden Daten vom Post-Prozessor verarbeitet */
            MHD_post_process(con_info->postprocessor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            /* POST-Daten sind vollständig empfangen */
            if (strcmp(url, "/send_encrypted_data") == 0) {
                /* Zum Debuggen: Ausgabe der empfangenen Daten */
                printf("Received POST data: %s\n", con_info->post_data);
                cJSON *json = cJSON_Parse(con_info->post_data);
                if (json == NULL) {
                    struct MHD_Response *response = create_response("{\"error\": \"Invalid JSON\"}");
                    int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                    MHD_destroy_response(response);
                    return ret;
                }
                /* Verarbeitung des JSON-Bodys */
                cJSON *ciphertext_json = cJSON_GetObjectItem(json, "ciphertext");
                cJSON *iv_json         = cJSON_GetObjectItem(json, "iv");
                cJSON *encrypted_data_json = cJSON_GetObjectItem(json, "data");

                if (!cJSON_IsString(ciphertext_json) ||
                    !cJSON_IsString(iv_json) ||
                    !cJSON_IsString(encrypted_data_json)) {
                    cJSON_Delete(json);
                    struct MHD_Response *response = create_response("{\"error\": \"Missing data\"}");
                    int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                    MHD_destroy_response(response);
                    return ret;
                }

                int ciphertext_len = 0, iv_len = 0, encrypted_data_len = 0;
                unsigned char *decoded_ciphertext = base64_decode(ciphertext_json->valuestring, &ciphertext_len);
                unsigned char *decoded_iv         = base64_decode(iv_json->valuestring, &iv_len);
                unsigned char *decoded_encrypted_data = base64_decode(encrypted_data_json->valuestring, &encrypted_data_len);

                if (!decoded_ciphertext ||
                    ciphertext_len != PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES ||
                    !decoded_iv || iv_len != 16 ||
                    !decoded_encrypted_data) {
                    cJSON_Delete(json);
                    free(decoded_ciphertext);
                    free(decoded_iv);
                    free(decoded_encrypted_data);
                    struct MHD_Response *response = create_response("{\"error\": \"Invalid base64 data\"}");
                    int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
                    MHD_destroy_response(response);
                    return ret;
                }

                uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
                unsigned char aes_key[32];
                unsigned char decrypted_data[4096];

                clock_t start_decap = clock();
                if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(shared_secret, decoded_ciphertext, global_secret_key) != 0) {
                    struct MHD_Response *response = create_response("{\"error\": \"Decapsulation failed\"}");
                    int ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
                    MHD_destroy_response(response);
                    cJSON_Delete(json);
                    free(decoded_ciphertext);
                    free(decoded_iv);
                    free(decoded_encrypted_data);
                    return ret;
                }
                clock_t end_decap = clock();

                SHA256(shared_secret, sizeof(shared_secret), aes_key);

                int decrypted_data_len = aes_decrypt(decoded_encrypted_data, encrypted_data_len, aes_key, decoded_iv, decrypted_data);
                (void)decrypted_data_len;

                char response_msg[256];
                snprintf(response_msg, sizeof(response_msg),
                         "{\"status\": \"Received\", \"decapsulation_time\": \"%f\", \"decrypted_data\": \"%.100s\"}",
                         (double)(end_decap - start_decap) / CLOCKS_PER_SEC, decrypted_data);

                struct MHD_Response *response = create_response(response_msg);
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
                MHD_destroy_response(response);

                cJSON_Delete(json);
                free(decoded_ciphertext);
                free(decoded_iv);
                free(decoded_encrypted_data);
                return ret;
            }
        }
    }
    /* GET-Request zur URL "/get_public_key" */
    else if (strcmp(method, "GET") == 0 && strcmp(url, "/get_public_key") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                            global_public_key, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }

    /* Standard-Antwort, wenn URL oder Methode nicht unterstützt wird */
    struct MHD_Response *response = create_response("{\"error\": \"Not found\"}");
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
}

int printIpAddress() {
    FILE *fp;
    char ip[64] = {0};
    fp = popen("ifconfig | grep 'inet ' | grep -m 1 -Po '192\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}'", "r");
    if (fp == NULL) {
        perror("popen failed");
        return EXIT_FAILURE;
    }
    if (fgets(ip, sizeof(ip), fp) != NULL) {
        ip[strcspn(ip, "\n")] = '\0';
    } else {
        fprintf(stderr, "Keine IP-Adresse gefunden.\n");
        pclose(fp);
        return EXIT_FAILURE;
    }
    pclose(fp);
    printf("Server is running on %s:%d\n", ip, PORT);
    return EXIT_SUCCESS;
}

int main() {
    /* 1. Asymmetrische Keypair-Generierung */
    if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(global_public_key, global_secret_key) != 0) {
        fprintf(stderr, "Failed to generate Kyber key pair.\n");
        return 1;
    }

    /* 2. HTTP-Server starten (ohne Verwendung von MHD_OPTION_POST_DATA_BUFFER_SIZE) */
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
                              &request_handler, NULL,
                              MHD_OPTION_NOTIFY_COMPLETED, request_completed_callback, NULL,
                              MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }

    printIpAddress();

    char input[128];
    while (1) {
        printf("Geben Sie 'stop' ein, um den Server zu beenden:\n");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        input[strcspn(input, "\r\n")] = '\0';
        for (int i = 0; input[i]; i++) {
            input[i] = tolower((unsigned char)input[i]);
        }
        if (strcmp(input, "stop") == 0) {
            break;
        }
    }

    MHD_stop_daemon(daemon);
    printf("Stopped Server\n");
    return 0;
}
