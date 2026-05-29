/*
 * PQC Keychain Generator -
 * Ternary SPX-QEC distillation pipeline DRIVES ALL keys
 * Now includes extra SPHINCS+ hybrid keypair + real BTC keys per role
 * Hybrid anchor = Role 0 BTC key
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>
#include <oqs/oqs.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#define TERNARY_LENGTH 6000
#define ROLE_COUNT 9
#define MASTER_POOL_SIZE 512

static unsigned char master_pool[MASTER_POOL_SIZE];
static size_t pool_idx = 0;

static void custom_randombytes(uint8_t *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (pool_idx >= MASTER_POOL_SIZE) {
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
            EVP_DigestUpdate(ctx, master_pool, MASTER_POOL_SIZE);
            EVP_DigestFinalXOF(ctx, master_pool, MASTER_POOL_SIZE);
            EVP_MD_CTX_free(ctx);
            pool_idx = 0;
        }
        output[i] = master_pool[pool_idx++];
    }
}

/* ==================== ORIGINAL TERNARY FUNCTIONS ==================== */
static char *generate_high_entropy_seed(void) {
    unsigned char raw[64];
    OQS_randombytes(raw, sizeof(raw));
    char *trits = (char *)malloc(513);
    for (int i = 0; i < 512; i++) trits[i] = '0' + (raw[i % 64] % 3);
    trits[512] = '\0';
    return trits;
}

static const char *BASE_PATTERNS[] = {
    "00", "11", "01", "10", "100", "011", "101", "010",
    "1001", "0110", "10100", "01011", "001101"
};
static const int BASE_PATTERNS_COUNT = 13;

typedef struct {
    char **patterns;
    int count;
} PatternList;

static PatternList build_spx_patterns(void) {
    PatternList result = {0};
    char temp[256];
    int capacity = 100;
    result.patterns = (char **)malloc(capacity * sizeof(char *));
    result.count = 0;
    for (int i = 0; i < BASE_PATTERNS_COUNT; i++) {
        const char *base = BASE_PATTERNS[i];
        int base_len = strlen(base);
        if (result.count >= capacity) { capacity *= 2; result.patterns = (char **)realloc(result.patterns, capacity * sizeof(char *)); }
        snprintf(temp, sizeof(temp), "%s%s", base, base + 1);
        result.patterns[result.count++] = strdup(temp);
        if (result.count >= capacity) { capacity *= 2; result.patterns = (char **)realloc(result.patterns, capacity * sizeof(char *)); }
        strcpy(temp, base);
        for (int j = 0; j < base_len / 2; j++) { char c = temp[j]; temp[j] = temp[base_len - 1 - j]; temp[base_len - 1 - j] = c; }
        result.patterns[result.count++] = strdup(temp);
        if (result.count >= capacity) { capacity *= 2; result.patterns = (char **)realloc(result.patterns, capacity * sizeof(char *)); }
        strcpy(temp, base);
        for (int j = 0; j < base_len / 2; j++) { char c = temp[j]; temp[j] = temp[base_len - 1 - j]; temp[base_len - 1 - j] = c; }
        snprintf(temp, sizeof(temp), "%s%s", base, temp);
        result.patterns[result.count++] = strdup(temp);
    }
    return result;
}

static void free_patterns(PatternList *plist) {
    for (int i = 0; i < plist->count; i++) free(plist->patterns[i]);
    free(plist->patterns);
}

static char *spx_qec_cleanup(const char *trits, int max_iterations) {
    char *cleaned = strdup(trits);
    PatternList patterns = build_spx_patterns();
    for (int iter = 0; iter < max_iterations; iter++) {
        char *prev = strdup(cleaned);
        for (int p = 0; p < patterns.count; p++) {
            char *pos = strstr(cleaned, patterns.patterns[p]);
            while (pos) {
                memmove(pos, pos + strlen(patterns.patterns[p]), strlen(pos + strlen(patterns.patterns[p])) + 1);
                pos = strstr(pos, patterns.patterns[p]);
            }
        }
        if (strlen(cleaned) == strlen(prev)) { free(prev); break; }
        free(prev);
    }
    free_patterns(&patterns);
    return cleaned;
}

static char *ternary_d_shift(const char *trits) {
    int len = strlen(trits);
    if (len == 0) return strdup("");
    char *result = (char *)malloc(len + 1);
    result[0] = trits[0];
    for (int i = 1; i < len; i++) {
        int prev = trits[i - 1] - '0';
        int nxt = trits[i] - '0';
        result[i] = (prev == nxt) ? '0' : (prev > nxt ? '1' : '2');
    }
    result[len] = '\0';
    return result;
}

static char *full_pass(const char *current, const char *prev) {
    int len = strlen(current);
    int n = len / 3;
    char *A = (char *)malloc(n + 1); char *B = (char *)malloc(n + 1); char *C = (char *)malloc(n + 1);
    strncpy(A, current, n); A[n] = '\0';
    strncpy(B, current + n, n); B[n] = '\0';
    strncpy(C, current + 2 * n, n); C[n] = '\0';
    char *new_A = ternary_d_shift(A); char *new_B = ternary_d_shift(B); char *new_C = ternary_d_shift(C);
    char *jump = (char *)malloc(n + 1);
    for (int i = 0; i < n; i++) {
        int a = new_A[i] - '0', b = new_B[i] - '0', c = new_C[i] - '0';
        jump[i] = '0' + (((a ^ b) + (c ^ b)) % 3);
    }
    jump[n] = '\0';
    char *B2 = (char *)malloc(2 * n + 1);
    if (prev && strlen(prev) >= n) {
        int prev_n = strlen(prev) / 3;
        strncpy(B2, prev + prev_n, n);
        strcpy(B2 + n, B);
    } else {
        strcpy(B2, B); strcpy(B2 + n, B);
    }
    char *xor_jump = (char *)malloc(n + 1);
    for (int i = 0; i < n && i < len; i++) {
        int x = current[i] - '0';
        int y = jump[i] - '0';
        xor_jump[i] = '0' + ((x ^ y) % 3);
    }
    xor_jump[n] = '\0';
    char *pass_str = (char *)malloc(len * 2 + 1);
    strcpy(pass_str, xor_jump); strcat(pass_str, B2);
    if (prev) {
        char *temp = pass_str;
        int temp_len = strlen(pass_str);
        int prev_len = strlen(prev);
        pass_str = (char *)malloc(temp_len + 1);
        for (int i = 0; i < temp_len && i < prev_len; i++)
            pass_str[i] = '0' + ((temp[i] - '0' + prev[i] - '0') % 3);
        for (int i = prev_len; i < temp_len; i++) pass_str[i] = temp[i];
        pass_str[temp_len] = '\0';
        free(temp);
    }
    int result_len = (len * 2 < strlen(pass_str)) ? len * 2 : strlen(pass_str);
    char *result = (char *)malloc(result_len + 1);
    strncpy(result, pass_str, result_len);
    result[result_len] = '\0';
    free(A); free(B); free(C); free(new_A); free(new_B); free(new_C);
    free(jump); free(B2); free(xor_jump); free(pass_str);
    return result;
}

static char *expand_to_10k_with_qec(const char *start) {
    char *current = strdup(start);
    char *prev = strdup(start);
    while (strlen(current) < 10000) {
        free(prev); prev = strdup(current);
        char *next = full_pass(current, prev);
        free(current);
        current = spx_qec_cleanup(next, 20);
        free(next);
        if (strlen(current) < strlen(prev) * 1.2) {
            char *temp = malloc(strlen(prev) * 2 + 1);
            strcpy(temp, prev); strncat(temp, current, strlen(prev));
            free(current); current = temp;
        }
    }
    free(prev);
    return current;
}

static char *reduce_to_6000_trits(const char *long_trits) {
    char *current = strdup(long_trits);
    for (int i = 0; i < 8; i++) {
        char *shifted = ternary_d_shift(current);
        free(current); current = shifted;
    }
    char *folded = malloc(TERNARY_LENGTH + 1);
    int current_len = strlen(current);
    for (int i = 0; i < TERNARY_LENGTH; i++) {
        int idx1 = (i * 17 + current_len) % current_len;
        int idx2 = (idx1 + current_len / 3) % current_len;
        folded[i] = '0' + (((current[idx1] - '0') ^ (current[idx2] - '0')) % 3);
    }
    folded[TERNARY_LENGTH] = '\0';
    free(current);
    return folded;
}

static void trit_to_master_pool(const char *final_trits) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
    EVP_DigestUpdate(ctx, (const unsigned char*)final_trits, strlen(final_trits));
    EVP_DigestFinalXOF(ctx, master_pool, MASTER_POOL_SIZE);
    EVP_MD_CTX_free(ctx);
    pool_idx = 0;
}

static void generate_keypair_set(const char *algo, unsigned char **pk, size_t *pk_len, unsigned char **sk, size_t *sk_len) {
    OQS_SIG *sig = OQS_SIG_new(algo);
    if (!sig) {
        fprintf(stderr, "ERROR: Failed to create %s context.\n", algo);
        exit(1);
    }
    *pk = malloc(sig->length_public_key);
    *sk = malloc(sig->length_secret_key);
    *pk_len = sig->length_public_key;
    *sk_len = sig->length_secret_key;
    OQS_randombytes_custom_algorithm(custom_randombytes);
    OQS_SIG_keypair(sig, *pk, *sk);
    OQS_randombytes_switch_algorithm("system");
    OQS_SIG_free(sig);
}

/* ==================== BTC secp256k1 key generation ==================== */
static int generate_btc_keypair(unsigned char **priv_out, size_t *priv_len_out,
                                unsigned char **pub_out, size_t *pub_len_out, int role) {
    *priv_len_out = 32;
    *priv_out = malloc(32);
    if (!*priv_out) return 0;

    if (role == 0) {
        custom_randombytes(*priv_out, 32);
    } else {
        unsigned char seed[64];
        custom_randombytes(seed, sizeof(seed));
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_shake256(), NULL);
        EVP_DigestUpdate(ctx, seed, sizeof(seed));
        EVP_DigestUpdate(ctx, (unsigned char*)&role, sizeof(role));
        EVP_DigestFinalXOF(ctx, *priv_out, 32);
        EVP_MD_CTX_free(ctx);
    }

    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM *priv_bn = BN_bin2bn(*priv_out, 32, NULL);
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!group || !priv_bn || !pub_point || !EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        BN_free(priv_bn); EC_POINT_free(pub_point); EC_GROUP_free((EC_GROUP*)group); return 0;
    }

    *pub_len_out = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    *pub_out = malloc(*pub_len_out);
    EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_COMPRESSED, *pub_out, *pub_len_out, NULL);

    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_GROUP_free((EC_GROUP*)group);
    return 1;
}

/* ==================== FILE I/O ==================== */
static char *get_timestamp_filename(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char *filename = malloc(256);
    strftime(filename, 256, "../svc-wallet/pqc_master_%Y%m%d_%H%M%S.kchain", tm_info);
    return filename;
}

static void ensure_svc_wallet_dir(void) { mkdir("../svc-wallet", 0755); }

static char *get_iso_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char *timestamp = malloc(32);
    strftime(timestamp, 32, "%Y-%m-%dT%H:%M:%SZ", tm_info);
    return timestamp;
}

static char *bytes_to_hex(const unsigned char *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) sprintf(hex + i * 2, "%02x", data[i]);
    hex[len * 2] = '\0';
    return hex;
}

/* ==================== MAIN ==================== */
int main(void) {
    srand(time(NULL));
    OQS_randombytes_switch_algorithm("system");
    printf("========== PQC Keychain Generator (SPX-QEC + Hybrid SPHINCS+BTC) ==========\n\n");

    char *epoch = generate_high_entropy_seed();
    printf("[1/7] Generating high-entropy 512-trit seed...\n Generated %zu ternary digits\n\n", strlen(epoch));

    char *pool = expand_to_10k_with_qec(epoch);
    printf("[2/7] Expanding to 10k+ trits with SPX-QEC...\n Expansion complete: %zu trits\n\n", strlen(pool));
    free(epoch);

    char *final_trits = reduce_to_6000_trits(pool);
    printf("[3/7] Finalizing to 6000-trit seed...\n Seed ready: %zu trits\n\n", strlen(final_trits));
    free(pool);

    printf("[4/7] Feeding distilled trits into master entropy pool...\n");
    trit_to_master_pool(final_trits);
    printf(" Master pool ready (SHAKE-256 expanded)\n\n");

    printf("[5/7] Generating Master keypairs (Falcon-512 + ML-DSA-65 + SLH-DSA + Hybrid SPHINCS+)...\n");
    unsigned char *f_pk, *f_sk, *d_pk, *d_sk, *s_pk, *s_sk, *h_pk, *h_sk;
    size_t f_pk_len, f_sk_len, d_pk_len, d_sk_len, s_pk_len, s_sk_len, h_pk_len, h_sk_len;
    generate_keypair_set("Falcon-512", &f_pk, &f_pk_len, &f_sk, &f_sk_len);
    generate_keypair_set("ML-DSA-65", &d_pk, &d_pk_len, &d_sk, &d_sk_len);
    generate_keypair_set("SLH_DSA_PURE_SHA2_128S", &s_pk, &s_pk_len, &s_sk, &s_sk_len);
    generate_keypair_set("SLH_DSA_PURE_SHA2_128S", &h_pk, &h_pk_len, &h_sk, &h_sk_len);
    printf(" Master keys generated\n\n");

    printf("[6/7] Generating 9 Role keypairs + BTC keys...\n");
    unsigned char *role_f_pk[ROLE_COUNT], *role_f_sk[ROLE_COUNT];
    unsigned char *role_d_pk[ROLE_COUNT], *role_d_sk[ROLE_COUNT];
    unsigned char *role_s_pk[ROLE_COUNT], *role_s_sk[ROLE_COUNT];
    unsigned char *role_h_pk[ROLE_COUNT], *role_h_sk[ROLE_COUNT];
    unsigned char *role_btc_priv[ROLE_COUNT], *role_btc_pub[ROLE_COUNT];
    size_t role_f_pk_len[ROLE_COUNT], role_f_sk_len[ROLE_COUNT];
    size_t role_d_pk_len[ROLE_COUNT], role_d_sk_len[ROLE_COUNT];
    size_t role_s_pk_len[ROLE_COUNT], role_s_sk_len[ROLE_COUNT];
    size_t role_h_pk_len[ROLE_COUNT], role_h_sk_len[ROLE_COUNT];
    size_t role_btc_priv_len[ROLE_COUNT], role_btc_pub_len[ROLE_COUNT];

    for (int r = 0; r < ROLE_COUNT; r++) {
        generate_keypair_set("Falcon-512", &role_f_pk[r], &role_f_pk_len[r], &role_f_sk[r], &role_f_sk_len[r]);
        generate_keypair_set("ML-DSA-65", &role_d_pk[r], &role_d_pk_len[r], &role_d_sk[r], &role_d_sk_len[r]);
        generate_keypair_set("SLH_DSA_PURE_SHA2_128S", &role_s_pk[r], &role_s_pk_len[r], &role_s_sk[r], &role_s_sk_len[r]);
        generate_keypair_set("SLH_DSA_PURE_SHA2_128S", &role_h_pk[r], &role_h_pk_len[r], &role_h_sk[r], &role_h_sk_len[r]);
        generate_btc_keypair(&role_btc_priv[r], &role_btc_priv_len[r], &role_btc_pub[r], &role_btc_pub_len[r], r);
        printf(" Role %d (hybrid SPHINCS+ + BTC) generated\n", r);
    }
    printf("\n");

    printf("Building JSON keychain with hybrid SPHINCS+BTC...\n");
    json_t *root = json_object();
    json_t *seed_obj = json_object();
    json_object_set_new(seed_obj, "ternary_6000_trits", json_string(final_trits));
    char *master_pool_hex = bytes_to_hex(master_pool, MASTER_POOL_SIZE);
    json_object_set_new(seed_obj, "master_pool_hex", json_string(master_pool_hex));
    json_object_set_new(root, "seed", seed_obj);

    json_t *keys_obj = json_object();
    char *falcon_pk_hex = bytes_to_hex(f_pk, f_pk_len);
    char *falcon_sk_hex = bytes_to_hex(f_sk, f_sk_len);
    char *dilithium_pk_hex = bytes_to_hex(d_pk, d_pk_len);
    char *dilithium_sk_hex = bytes_to_hex(d_sk, d_sk_len);
    char *sphincs_pk_hex = bytes_to_hex(s_pk, s_pk_len);
    char *sphincs_sk_hex = bytes_to_hex(s_sk, s_sk_len);
    char *hybrid_pk_hex = bytes_to_hex(h_pk, h_pk_len);
    char *hybrid_sk_hex = bytes_to_hex(h_sk, h_sk_len);

    json_object_set_new(keys_obj, "falcon_512_master_pk", json_string(falcon_pk_hex));
    json_object_set_new(keys_obj, "falcon_512_master_sk", json_string(falcon_sk_hex));
    json_object_set_new(keys_obj, "dilithium3_master_pk", json_string(dilithium_pk_hex));
    json_object_set_new(keys_obj, "dilithium3_master_sk", json_string(dilithium_sk_hex));
    json_object_set_new(keys_obj, "sphincs128s_master_pk", json_string(sphincs_pk_hex));
    json_object_set_new(keys_obj, "sphincs128s_master_sk", json_string(sphincs_sk_hex));
    json_object_set_new(keys_obj, "sphincs128s_hybrid_master_pk", json_string(hybrid_pk_hex));
    json_object_set_new(keys_obj, "sphincs128s_hybrid_master_sk", json_string(hybrid_sk_hex));

    json_t *roles_array = json_array();
    for (int role = 0; role < ROLE_COUNT; role++) {
        json_t *role_obj = json_object();
        json_object_set_new(role_obj, "role", json_integer(role));

        char *f_pk_h = bytes_to_hex(role_f_pk[role], role_f_pk_len[role]);
        char *f_sk_h = bytes_to_hex(role_f_sk[role], role_f_sk_len[role]);
        char *d_pk_h = bytes_to_hex(role_d_pk[role], role_d_pk_len[role]);
        char *d_sk_h = bytes_to_hex(role_d_sk[role], role_d_sk_len[role]);
        char *s_pk_h = bytes_to_hex(role_s_pk[role], role_s_pk_len[role]);
        char *s_sk_h = bytes_to_hex(role_s_sk[role], role_s_sk_len[role]);
        char *h_pk_h = bytes_to_hex(role_h_pk[role], role_h_pk_len[role]);
        char *h_sk_h = bytes_to_hex(role_h_sk[role], role_h_sk_len[role]);

        json_object_set_new(role_obj, "falcon_512_pk", json_string(f_pk_h));
        json_object_set_new(role_obj, "falcon_512_sk", json_string(f_sk_h));
        json_object_set_new(role_obj, "dilithium3_pk", json_string(d_pk_h));
        json_object_set_new(role_obj, "dilithium3_sk", json_string(d_sk_h));
        json_object_set_new(role_obj, "sphincs128s_pk", json_string(s_pk_h));
        json_object_set_new(role_obj, "sphincs128s_sk", json_string(s_sk_h));
        json_object_set_new(role_obj, "sphincs128s_hybrid_pk", json_string(h_pk_h));
        json_object_set_new(role_obj, "sphincs128s_hybrid_sk", json_string(h_sk_h));

        json_t *btc_obj = json_object();
        char *btc_priv_h = bytes_to_hex(role_btc_priv[role], role_btc_priv_len[role]);
        char *btc_pub_h = bytes_to_hex(role_btc_pub[role], role_btc_pub_len[role]);
        json_object_set_new(btc_obj, "private_key_hex", json_string(btc_priv_h));
        json_object_set_new(btc_obj, "public_key_hex", json_string(btc_pub_h));
        json_object_set_new(btc_obj, "is_hybrid_anchor", json_boolean(role == 0));
        json_object_set_new(role_obj, "bitcoin", btc_obj);

        json_array_append_new(roles_array, role_obj);

        free(f_pk_h); free(f_sk_h); free(d_pk_h); free(d_sk_h); free(s_pk_h); free(s_sk_h);
        free(h_pk_h); free(h_sk_h); free(btc_priv_h); free(btc_pub_h);
    }
    json_object_set_new(keys_obj, "roles", roles_array);
    json_object_set_new(root, "keys", keys_obj);

    char *timestamp = get_iso_timestamp();
    json_object_set_new(root, "generated_at", json_string(timestamp));
    json_object_set_new(root, "algorithm", json_string("Falcon-512 + ML-DSA-65 + SLH-DSA-SHA2-128s (SPHINCS+) + Hybrid SPHINCS+BTC"));
    json_object_set_new(root, "library", json_string("liboqs 0.12.x + OpenSSL secp256k1"));
    json_object_set_new(root, "note", json_string("All keys driven by SPX-QEC. Hybrid SPHINCS+BTC added per upgrade plan."));

    ensure_svc_wallet_dir();
    char *filename = get_timestamp_filename();
    json_dump_file(root, filename, JSON_INDENT(2));
    printf("✅ Keychain saved to: %s\n\n", filename);

    /* cleanup */
    free(final_trits); free(master_pool_hex); free(falcon_pk_hex); free(falcon_sk_hex);
    free(dilithium_pk_hex); free(dilithium_sk_hex); free(sphincs_pk_hex); free(sphincs_sk_hex);
    free(hybrid_pk_hex); free(hybrid_sk_hex); free(timestamp); free(filename);

    free(f_pk); free(f_sk); free(d_pk); free(d_sk); free(s_pk); free(s_sk); free(h_pk); free(h_sk);

    for (int r = 0; r < ROLE_COUNT; r++) {
        free(role_f_pk[r]); free(role_f_sk[r]);
        free(role_d_pk[r]); free(role_d_sk[r]);
        free(role_s_pk[r]); free(role_s_sk[r]);
        free(role_h_pk[r]); free(role_h_sk[r]);
        free(role_btc_priv[r]); free(role_btc_pub[r]);
    }
    json_decref(root);

    printf("✅ Complete! Hybrid SPHINCS+BTC keys are now included and fully generated.\n");
    return 0;
}
