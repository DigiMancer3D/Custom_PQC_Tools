/*
 * pqc_key_validator.c
 * ROBUST + OFFICIAL version for ternaryPQC
 *
 * Full validation tool for Falcon-512 + Dilithium3 keys
 * Tolerant to whitespace, newlines, extra formatting, etc.
 */

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <oqs/oqs.h>

static const char* skip_whitespace(const char* p) {
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

/* Returns pointer right after the ':' of the requested key, or NULL */
static const char* find_key(const char* haystack, const char* key_name) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key_name);

    const char* pos = haystack;
    while ((pos = strstr(pos, pattern)) != NULL) {
        const char* after = pos + strlen(pattern);
        after = skip_whitespace(after);
        if (*after == ':') {
            return after + 1;   // right after the colon
        }
        pos += 1;  // continue searching for next occurrence
    }
    return NULL;
}

static char* extract_string_value(const char* after_colon) {
    const char* p = skip_whitespace(after_colon);
    if (*p != '"') return NULL;
    p++;  // skip opening quote

    const char* end = strchr(p, '"');
    if (!end) return NULL;

    size_t len = end - p;
    char* value = malloc(len + 1);
    if (!value) return NULL;
    strncpy(value, p, len);
    value[len] = '\0';
    return value;
}

static char* extract_value_robust(const char* json, const char* key_name) {
    const char* after_colon = find_key(json, key_name);
    if (!after_colon) return NULL;
    return extract_string_value(after_colon);
}

static char* extract_role_key_robust(const char* json, int role_num, const char* key_suffix) {
    char role_pattern[64];
    snprintf(role_pattern, sizeof(role_pattern), "\"role\"");

    const char* pos = json;
    while ((pos = strstr(pos, role_pattern)) != NULL) {
        const char* after = pos + strlen("\"role\"");
        after = skip_whitespace(after);
        if (*after == ':') {
            after++;
            after = skip_whitespace(after);

            int found_role = -1;
            if (sscanf(after, "%d", &found_role) == 1 && found_role == role_num) {
                /* Found the correct role object - now find the desired key from here onward */
                const char* key_after = find_key(pos, key_suffix);
                if (key_after) {
                    return extract_string_value(key_after);
                }
            }
        }
        pos += 1;  // move past this occurrence
    }
    return NULL;
}

static int hex_to_bytes(const char* hex, uint8_t** bytes_out, size_t* len_out) {
    if (!hex) return 0;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;
    *len_out = hex_len / 2;
    *bytes_out = malloc(*len_out);
    if (!*bytes_out) return 0;

    for (size_t i = 0; i < *len_out; i++) {
        if (sscanf(hex + 2 * i, "%2hhx", &(*bytes_out)[i]) != 1) {
            free(*bytes_out);
            return 0;
        }
    }
    return 1;
}

static int test_keypair(const char* algo_name, const char* pk_hex, const char* sk_hex, const char* label) {
    printf("Testing %s (%s)...\n", label, algo_name);

    OQS_SIG* sig = OQS_SIG_new(algo_name);
    if (!sig) {
        printf("   FAILED: Could not create OQS_SIG for %s\n", algo_name);
        return 0;
    }

    uint8_t* pk = NULL; uint8_t* sk = NULL;
    size_t pk_len = 0, sk_len = 0;

    if (!hex_to_bytes(pk_hex, &pk, &pk_len) || !hex_to_bytes(sk_hex, &sk, &sk_len)) {
        printf("   FAILED: Hex decoding error\n");
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return 0;
    }

    if (pk_len != sig->length_public_key || sk_len != sig->length_secret_key) {
        printf("   FAILED: Wrong key length (pk=%zu, sk=%zu, expected pk=%zu sk=%zu)\n",
               pk_len, sk_len, sig->length_public_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(pk); free(sk);
        return 0;
    }

    const uint8_t msg[] = "PQC role validation test message - 2026";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t* signature = malloc(sig->length_signature);
    size_t sig_len = 0;

    OQS_STATUS rc = OQS_SIG_sign(sig, signature, &sig_len, msg, msg_len, sk);
    if (rc != OQS_SUCCESS) {
        printf("   FAILED: OQS_SIG_sign failed\n");
        OQS_SIG_free(sig);
        free(pk); free(sk); free(signature);
        return 0;
    }

    rc = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pk);
    if (rc != OQS_SUCCESS) {
        printf("   FAILED: OQS_SIG_verify failed (signature invalid)\n");
        OQS_SIG_free(sig);
        free(pk); free(sk); free(signature);
        return 0;
    }

    printf("   PASS ✓\n");
    OQS_SIG_free(sig);
    free(pk); free(sk); free(signature);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path-to-pasted-text.txt>\n", argv[0]);
        fprintf(stderr, "       (point it at any .kchain file inside your svc-wallet/ folder)\n");
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open .kchain file");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    char* json = malloc(fsize + 1);
    if (!json) {
        fclose(f);
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    size_t bytes_read = fread(json, 1, fsize, f);
    fclose(f);

    if (bytes_read != (size_t)fsize) {
        fprintf(stderr, "Failed to read entire file (read %zu of %ld bytes)\n", bytes_read, fsize);
        free(json);
        return 1;
    }
    json[fsize] = '\0';

    printf("=== PQC Key Validation Tool (ROBUST version - liboqs 0.12.x) ===\n\n");

    char* falcon_master_pk = extract_value_robust(json, "falcon_512_master_pk");
    char* falcon_master_sk = extract_value_robust(json, "falcon_512_master_sk");
    char* dilithium_master_pk = extract_value_robust(json, "dilithium3_master_pk");
    char* dilithium_master_sk = extract_value_robust(json, "dilithium3_master_sk");

    int all_pass = 1;

    if (!test_keypair("Falcon-512", falcon_master_pk, falcon_master_sk, "Master Falcon-512")) all_pass = 0;
    if (!test_keypair("Dilithium3", dilithium_master_pk, dilithium_master_sk, "Master Dilithium3")) all_pass = 0;

    free(falcon_master_pk); free(falcon_master_sk);
    free(dilithium_master_pk); free(dilithium_master_sk);

    int role_ids[] = {0, 1, 5, 6, 7};
    const char* role_names[] = {"Role 0", "Role 1", "Role 5", "Role 6", "Role 7"};

    for (int i = 0; i < 5; i++) {
        int role_num = role_ids[i];
        printf("\n--- %s ---\n", role_names[i]);

        char* falcon_pk = extract_role_key_robust(json, role_num, "falcon_512_pk");
        char* falcon_sk = extract_role_key_robust(json, role_num, "falcon_512_sk");
        char* dilithium_pk = extract_role_key_robust(json, role_num, "dilithium3_pk");
        char* dilithium_sk = extract_role_key_robust(json, role_num, "dilithium3_sk");

        if (!test_keypair("Falcon-512", falcon_pk, falcon_sk, "Falcon-512")) all_pass = 0;
        if (!test_keypair("Dilithium3", dilithium_pk, dilithium_sk, "Dilithium3")) all_pass = 0;

        free(falcon_pk); free(falcon_sk);
        free(dilithium_pk); free(dilithium_sk);
    }

    free(json);

    printf("\n=== FINAL RESULT ===\n");
    if (all_pass) {
        printf("ALL KEYS ARE CRYPTOGRAPHICALLY VALID ✓\n");
        printf("You can safely use these keys in your process-separation program.\n");
    } else {
        printf("SOME KEYS FAILED! Check the output above.\n");
    }

    return all_pass ? 0 : 1;
}
