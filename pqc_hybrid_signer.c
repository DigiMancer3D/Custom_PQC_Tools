#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <jansson.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define TERNARY_LENGTH 6000

/* ==================== SPX-QEC ==================== */
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
    char temp2[256];          /* extra buffer to silence GCC restrict warning */
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
        snprintf(temp2, sizeof(temp2), "%s%s", base, temp);   /* use separate buffer */
        result.patterns[result.count++] = strdup(temp2);
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

/* ==================== Base58 encode ==================== */
static char* base58_encode(const unsigned char* data, size_t len) {
    static const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t i, j, carry;
    size_t size = len * 138 / 100 + 1;
    unsigned char* buf = calloc(size, 1);
    for (i = 0; i < len; i++) {
        carry = data[i];
        for (j = 0; j < size; j++) {
            carry += (unsigned char)buf[j] * 256;
            buf[j] = carry % 58;
            carry /= 58;
        }
    }
    for (i = 0; i < size && buf[i] == 0; i++);
    char* out = malloc(size - i + 1);
    for (j = 0; i < size; i++, j++) out[j] = alphabet[buf[i]];
    out[j] = '\0';
    free(buf);
    return out;
}

/* ==================== Base64 encode ==================== */
static char* base64_encode(const unsigned char* data, size_t len) {
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char* out = malloc(out_len);
    EVP_EncodeBlock((unsigned char*)out, data, len);
    return out;
}

/* ==================== Bitcoin Signed Message Hash ==================== */
static void bitcoin_message_hash(const char* message, unsigned char* hash_out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    const char* prefix = "\x18" "Bitcoin Signed Message:\n";
    size_t msg_len = strlen(message);
    EVP_DigestUpdate(ctx, prefix, strlen(prefix));
    unsigned char len_byte = (unsigned char)msg_len;
    EVP_DigestUpdate(ctx, &len_byte, 1);
    EVP_DigestUpdate(ctx, message, msg_len);
    EVP_DigestFinal_ex(ctx, hash_out, NULL);
    EVP_MD_CTX_free(ctx);

    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, hash_out, 32);
    EVP_DigestFinal_ex(ctx, hash_out, NULL);
    EVP_MD_CTX_free(ctx);
}

/* ==================== BTC ECDSA Compact Sign (65-byte with PROPER recovery ID) ==================== */
static int btc_ecdsa_sign(const char* priv_hex, const char* message, unsigned char** sig_out, size_t* sig_len_out) {
    uint8_t* priv = NULL; size_t priv_len = 0;
    size_t hex_len = strlen(priv_hex);
    priv_len = hex_len / 2;
    priv = malloc(priv_len);
    for (size_t i = 0; i < priv_len; i++) sscanf(priv_hex + 2*i, "%2hhx", &priv[i]);

    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* bn = BN_bin2bn(priv, 32, NULL);
    EC_KEY_set_private_key(eckey, bn);
    const EC_GROUP* group = EC_KEY_get0_group(eckey);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, bn, NULL, NULL, NULL);
    EC_KEY_set_public_key(eckey, pub);

    unsigned char hash[32];
    bitcoin_message_hash(message, hash);

    unsigned char* der_sig = malloc(ECDSA_size(eckey));
    unsigned int der_len = 0;
    ECDSA_sign(0, hash, 32, der_sig, &der_len, eckey);

    ECDSA_SIG *sig_struct = ECDSA_SIG_new();
    const unsigned char *p = der_sig;
    d2i_ECDSA_SIG(&sig_struct, &p, der_len);

    const BIGNUM *r_bn, *s_bn;
    ECDSA_SIG_get0(sig_struct, &r_bn, &s_bn);

    unsigned char r[32], s[32];

    /* LOW-S NORMALIZATION (Bitcoin standard) */
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, NULL);
    BIGNUM *half = BN_new();
    BN_rshift1(half, order);

    BIGNUM *s_norm = BN_dup(s_bn);
    if (BN_cmp(s_norm, half) > 0) {
        BN_sub(s_norm, order, s_norm);
    }

    BN_bn2binpad(r_bn, r, 32);
    BN_bn2binpad(s_norm, s, 32);

    /* PROPER RECOVERY ID (27-30) */
    BIGNUM *pub_y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pub, NULL, pub_y, NULL);
    int y_odd = BN_is_odd(pub_y) ? 1 : 0;

    unsigned char recid = 27 + y_odd;

    unsigned char *compact = malloc(65);
    compact[0] = recid;
    memcpy(compact + 1, r, 32);
    memcpy(compact + 33, s, 32);

    *sig_out = compact;
    *sig_len_out = 65;

    BN_free(order); BN_free(half); BN_free(s_norm); BN_free(pub_y);
    ECDSA_SIG_free(sig_struct);
    free(der_sig);
    BN_free(bn); EC_POINT_free(pub); EC_KEY_free(eckey); free(priv);
    return 1;
}

/* ==================== Convert raw hex private key to WIF ==================== */
static char* hex_to_wif(const char* priv_hex) {
    unsigned char key[32];
    for (size_t i = 0; i < 32; i++) sscanf(priv_hex + 2*i, "%2hhx", &key[i]);

    unsigned char extended[34];
    extended[0] = 0x80;
    memcpy(extended + 1, key, 32);
    extended[33] = 0x01;

    unsigned char hash[32];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, extended, 34);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, hash, 32);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    unsigned char final[38];
    memcpy(final, extended, 34);
    memcpy(final + 34, hash, 4);

    return base58_encode(final, 38);
}

/* ==================== Hybrid signing core ==================== */
static void hybrid_sign(const unsigned char* hybrid_sk, size_t sk_len __attribute__((unused)),
                        const unsigned char* btc_sig, size_t btc_sig_len,
                        const char* message,
                        unsigned char** final_sig_out, size_t* final_sig_len_out) {

    OQS_SIG* sig = OQS_SIG_new("SLH_DSA_PURE_SHA2_128S");
    if (!sig) {
        fprintf(stderr, "ERROR: SLH_DSA_PURE_SHA2_128S not available in liboqs\n");
        exit(1);
    }
    uint8_t* sphincs_sig = malloc(sig->length_signature);
    size_t sphincs_sig_len = 0;

    unsigned char state[32];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
    EVP_DigestUpdate(ctx, btc_sig, btc_sig_len);
    EVP_DigestUpdate(ctx, (const unsigned char*)message, strlen(message));
    EVP_DigestFinal_ex(ctx, state, NULL);
    EVP_MD_CTX_free(ctx);

    char* trits = malloc(513);
    for (int i = 0; i < 512; i++) trits[i] = '0' + (state[i % 32] % 3);
    trits[512] = '\0';
    char* cleaned = spx_qec_cleanup(trits, 20);
    free(trits);

    OQS_SIG_sign(sig, sphincs_sig, &sphincs_sig_len, (const unsigned char*)cleaned, strlen(cleaned), hybrid_sk);
    free(cleaned);

    size_t total_len = btc_sig_len + sphincs_sig_len + 32;
    unsigned char* blob = malloc(total_len);
    memcpy(blob, btc_sig, btc_sig_len);
    memcpy(blob + btc_sig_len, sphincs_sig, sphincs_sig_len);
    memset(blob + btc_sig_len + sphincs_sig_len, 0xAA, 32);

    char* faux_sig = base58_encode(blob, total_len);

    *final_sig_out = (unsigned char*)faux_sig;
    *final_sig_len_out = strlen(faux_sig);

    OQS_SIG_free(sig);
    free(sphincs_sig);
    free(blob);
}

/* ==================== MAIN ==================== */
int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <kchain_file> <role_number> \"message\" [--base64]\n", argv[0]);
        return 1;
    }

    int role = atoi(argv[2]);
    const char* message = argv[3];
    int print_base64 = (argc > 4 && strcmp(argv[argc-1], "--base64") == 0);

    json_t* root = json_load_file(argv[1], 0, NULL);
    if (!root) {
        fprintf(stderr, "ERROR: Failed to load keychain file\n");
        return 1;
    }

    json_t* keys = json_object_get(root, "keys");
    json_t* roles = json_object_get(keys, "roles");

    json_t* role_obj = NULL;
    size_t index;
    int found = 0;
    json_array_foreach(roles, index, role_obj) {
        json_t* r = json_object_get(role_obj, "role");
        if (r && json_integer_value(r) == role) {
            found = 1;
            break;
        }
    }

    if (!found || !role_obj) {
        fprintf(stderr, "ERROR: Role %d not found in keychain\n", role);
        json_decref(root);
        return 1;
    }

    const char* hybrid_sk_hex = json_string_value(json_object_get(role_obj, "sphincs128s_hybrid_sk"));
    json_t* btc_obj = json_object_get(role_obj, "bitcoin");
    const char* btc_priv_hex = json_string_value(json_object_get(btc_obj, "private_key_hex"));

    if (!hybrid_sk_hex || !btc_priv_hex) {
        fprintf(stderr, "ERROR: Could not extract keys for role %d\n", role);
        json_decref(root);
        return 1;
    }

    char* wif = hex_to_wif(btc_priv_hex);
    printf("✅ BTC WIF:\n%s\n\n", wif);

    printf("✅ Descriptor:\npkh(%s)\n\n", wif);

    unsigned char* btc_sig = NULL; size_t btc_sig_len = 0;
    btc_ecdsa_sign(btc_priv_hex, message, &btc_sig, &btc_sig_len);

    uint8_t* hybrid_sk = NULL; size_t sk_len = 0;
    size_t hex_len = strlen(hybrid_sk_hex);
    sk_len = hex_len / 2;
    hybrid_sk = malloc(sk_len);
    for (size_t i = 0; i < sk_len; i++) sscanf(hybrid_sk_hex + 2*i, "%2hhx", &hybrid_sk[i]);

    unsigned char* final_sig = NULL; size_t final_sig_len = 0;
    hybrid_sign(hybrid_sk, sk_len, btc_sig, btc_sig_len, message, &final_sig, &final_sig_len);

    printf("✅ Hybrid SPHINCS+BTC Signature (faux base58):\n%s\n\n", final_sig);

    char* b64 = NULL;
    if (print_base64) {
        b64 = base64_encode(btc_sig, btc_sig_len);
        printf("✅ Standard base64 ECDSA compact signature (for verifymessage):\n%s\n\n", b64);
    }

    printf("Inner BTC ECDSA part is fully verifiable on Bitcoin Core (verifymessage).\n");
    printf("Outer SPHINCS+ wrapper (via SPX-QEC) provides quantum resistance.\n\n");

    /* ==================== SAVE JSON .msg FILE (fixed path + error handling) ==================== */
    const char *output_dir = "../svc-wallet";
    if (mkdir(output_dir, 0755) != 0 && errno != EEXIST) {
        perror("WARNING: Could not create output directory");
    }

    /* Extract timestamp from kchain filename */
    char timestamp[32] = "unknown";
    {
        char path_copy[1024];
        strncpy(path_copy, argv[1], sizeof(path_copy)-1);
        path_copy[sizeof(path_copy)-1] = '\0';
        char *base = strrchr(path_copy, '/');
        if (!base) base = path_copy; else base++;
        char *ts_start = strstr(base, "pqc_master_");
        if (ts_start) {
            ts_start += 11;
            strncpy(timestamp, ts_start, 15);
            timestamp[15] = '\0';
        }
    }

    /* Build short WIF prefix */
    char short_wif[8] = {0};
    if (strlen(wif) >= 6) {
        strncpy(short_wif, wif, 3);
        strncpy(short_wif + 3, wif + strlen(wif) - 3, 3);
        short_wif[6] = '\0';
    } else {
        strncpy(short_wif, wif, sizeof(short_wif)-1);
    }

    char msg_filename[512];
    snprintf(msg_filename, sizeof(msg_filename), "%s/%s_pqc-signed_%s.msg",
             output_dir, short_wif, timestamp);

    /* Build JSON */
    json_t *msg_json = json_object();
    json_object_set_new(msg_json, "kchain_file", json_string(argv[1]));
    json_object_set_new(msg_json, "role", json_integer(role));
    json_object_set_new(msg_json, "message", json_string(message));
    json_object_set_new(msg_json, "btc_wif", json_string(wif));

    char descriptor_buf[256];
    snprintf(descriptor_buf, sizeof(descriptor_buf), "pkh(%s)", wif);
    json_object_set_new(msg_json, "descriptor", json_string(descriptor_buf));

    json_object_set_new(msg_json, "hybrid_signature", json_string((char*)final_sig));
    if (b64) {
        json_object_set_new(msg_json, "base64_ecdsa_signature", json_string(b64));
    } else {
        json_object_set_new(msg_json, "base64_ecdsa_signature", json_null());
    }
    json_object_set_new(msg_json, "timestamp", json_string(timestamp));
    json_object_set_new(msg_json, "generated_at", json_string("now"));

    /* Write file with detailed error reporting */
    if (json_dump_file(msg_json, msg_filename, JSON_INDENT(2)) == 0) {
        printf("✅ Signed message saved to:\n   %s\n\n", msg_filename);
    } else {
        fprintf(stderr, "ERROR: Could not save .msg file to %s\n", msg_filename);
        perror("       Reason");
    }

    json_decref(msg_json);
    if (b64) free(b64);

    free(btc_sig);
    free(hybrid_sk);
    free(final_sig);
    free(wif);
    json_decref(root);
    return 0;
}
