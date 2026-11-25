#include "pkcs11.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

#define CASE_COUNT 5
#define MSG_LEN 512

typedef struct {
    const char *id;
    int failed;
    long duration_ms;
    char message[MSG_LEN];
} Case;

typedef struct {
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    char label[64];
    int session_open;
    int key_live;
    char error[MSG_LEN];
} Ctx;

static int fail(Case *c, const char *fmt, ...) {
    va_list ap;
    c->failed = 1;
    va_start(ap, fmt);
    vsnprintf(c->message, sizeof(c->message), fmt, ap);
    va_end(ap);
    return -1;
}

static void trim_copy(char *dst, size_t dst_len, const unsigned char *src, size_t src_len) {
    size_t end = src_len;
    while (end > 0 && (src[end - 1] == ' ' || src[end - 1] == '\0')) {
        end--;
    }
    if (end >= dst_len) {
        end = dst_len - 1;
    }
    memcpy(dst, src, end);
    dst[end] = '\0';
}

static int find_slot(Ctx *ctx, const char *label) {
    CK_ULONG count = 0;
    CK_RV rv = C_GetSlotList(CK_TRUE, NULL, &count);
    if (rv != CKR_OK) {
        snprintf(ctx->error, sizeof(ctx->error), "C_GetSlotList failed: 0x%lx", rv);
        return -1;
    }
    if (count == 0) {
        snprintf(ctx->error, sizeof(ctx->error), "no PKCS#11 token is present");
        return -1;
    }
    CK_SLOT_ID *slots = calloc(count, sizeof(CK_SLOT_ID));
    if (slots == NULL) {
        snprintf(ctx->error, sizeof(ctx->error), "out of memory");
        return -1;
    }
    rv = C_GetSlotList(CK_TRUE, slots, &count);
    if (rv != CKR_OK) {
        free(slots);
        snprintf(ctx->error, sizeof(ctx->error), "C_GetSlotList failed: 0x%lx", rv);
        return -1;
    }
    int found = 0;
    for (CK_ULONG i = 0; i < count; i++) {
        unsigned char info[512];
        memset(info, 0, sizeof(info));
        rv = C_GetTokenInfo(slots[i], info);
        if (rv != CKR_OK) {
            continue;
        }
        char current[33];
        trim_copy(current, sizeof(current), info, 32);
        if (strcmp(current, label) == 0) {
            ctx->slot = slots[i];
            found = 1;
            break;
        }
    }
    free(slots);
    if (!found) {
        snprintf(ctx->error, sizeof(ctx->error), "token '%s' not found", label);
        return -1;
    }
    return 0;
}

static int case_wrong_pin(Ctx *ctx, Case *c) {
    CK_SESSION_HANDLE session = 0;
    CK_RV rv = C_OpenSession(ctx->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) {
        return fail(c, "C_OpenSession failed: 0x%lx", rv);
    }
    const char *bad = "WRONG-PIN-SENTINEL";
    rv = C_Login(session, CKU_USER, (CK_UTF8CHAR *)bad, (CK_ULONG)strlen(bad));
    C_CloseSession(session);
    if (rv != CKR_PIN_INCORRECT) {
        return fail(c, "expected CKR_PIN_INCORRECT (0xa0), got 0x%lx", rv);
    }
    snprintf(c->message, sizeof(c->message), "CKR_PIN_INCORRECT");
    return 0;
}

static int case_login(Ctx *ctx, Case *c) {
    const char *pin = getenv("HSM_PIN");
    if (pin == NULL || pin[0] == '\0') {
        return fail(c, "HSM_PIN is not set");
    }
    CK_RV rv = C_OpenSession(ctx->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &ctx->session);
    if (rv != CKR_OK) {
        return fail(c, "C_OpenSession failed: 0x%lx", rv);
    }
    ctx->session_open = 1;
    rv = C_Login(ctx->session, CKU_USER, (CK_UTF8CHAR *)pin, (CK_ULONG)strlen(pin));
    if (rv != CKR_OK) {
        return fail(c, "C_Login failed: 0x%lx", rv);
    }
    snprintf(c->message, sizeof(c->message), "session open on slot %lu", ctx->slot);
    return 0;
}

static int case_generate(Ctx *ctx, Case *c) {
    if (!ctx->session_open) {
        return fail(c, "no session");
    }
    snprintf(ctx->label, sizeof(ctx->label), "c-aes-%ld", (long)getpid());
    CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_CLASS cko = CKO_SECRET_KEY;
    CK_KEY_TYPE ck_aes = CKK_AES;
    CK_ULONG value_len = 32;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &cko, sizeof(cko)},
        {CKA_KEY_TYPE, &ck_aes, sizeof(ck_aes)},
        {CKA_VALUE_LEN, &value_len, sizeof(value_len)},
        {CKA_TOKEN, &ck_true, sizeof(ck_true)},
        {CKA_PRIVATE, &ck_true, sizeof(ck_true)},
        {CKA_SENSITIVE, &ck_true, sizeof(ck_true)},
        {CKA_EXTRACTABLE, &ck_true, sizeof(ck_true)},
        {CKA_ENCRYPT, &ck_true, sizeof(ck_true)},
        {CKA_DECRYPT, &ck_true, sizeof(ck_true)},
        {CKA_LABEL, ctx->label, (CK_ULONG)strlen(ctx->label)},
    };
    CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL, 0};
    CK_RV rv = C_GenerateKey(ctx->session, &mech, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), &ctx->key);
    if (rv != CKR_OK) {
        return fail(c, "C_GenerateKey failed: 0x%lx", rv);
    }
    ctx->key_live = 1;
    CK_BYTE buffer[32];
    memset(buffer, 0, sizeof(buffer));
    CK_ATTRIBUTE value = {CKA_VALUE, buffer, sizeof(buffer)};
    rv = C_GetAttributeValue(ctx->session, ctx->key, &value, 1);
    if (rv != CKR_ATTRIBUTE_SENSITIVE) {
        return fail(c, "expected CKR_ATTRIBUTE_SENSITIVE (0x11), got 0x%lx", rv);
    }
    snprintf(c->message, sizeof(c->message), "CKA_VALUE -> CKR_ATTRIBUTE_SENSITIVE");
    return 0;
}

static int case_roundtrip(Ctx *ctx, Case *c) {
    if (!ctx->key_live) {
        return fail(c, "no key");
    }
    CK_BYTE iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = (CK_BYTE)(0xA0 + i);
    }
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, iv, sizeof(iv)};
    const char *plain = "tnr-c-campaign";
    CK_ULONG plain_len = (CK_ULONG)strlen(plain);
    CK_BYTE cipher[64];
    CK_ULONG cipher_len = sizeof(cipher);
    CK_RV rv = C_EncryptInit(ctx->session, &mech, ctx->key);
    if (rv != CKR_OK) {
        return fail(c, "C_EncryptInit failed: 0x%lx", rv);
    }
    rv = C_Encrypt(ctx->session, (CK_BYTE *)plain, plain_len, cipher, &cipher_len);
    if (rv != CKR_OK) {
        return fail(c, "C_Encrypt failed: 0x%lx", rv);
    }
    CK_BYTE back[64];
    CK_ULONG back_len = sizeof(back);
    rv = C_DecryptInit(ctx->session, &mech, ctx->key);
    if (rv != CKR_OK) {
        return fail(c, "C_DecryptInit failed: 0x%lx", rv);
    }
    rv = C_Decrypt(ctx->session, cipher, cipher_len, back, &back_len);
    if (rv != CKR_OK) {
        return fail(c, "C_Decrypt failed: 0x%lx", rv);
    }
    if (back_len != plain_len || memcmp(back, plain, plain_len) != 0) {
        return fail(c, "plaintext mismatch after decrypt");
    }
    snprintf(c->message, sizeof(c->message), "AES-CBC-PAD round trip, %lu ciphertext bytes", cipher_len);
    return 0;
}

static int find_count(Ctx *ctx, CK_ULONG *count) {
    CK_ATTRIBUTE tmpl[] = {
        {CKA_LABEL, ctx->label, (CK_ULONG)strlen(ctx->label)},
    };
    CK_RV rv = C_FindObjectsInit(ctx->session, tmpl, 1);
    if (rv != CKR_OK) {
        return -1;
    }
    CK_OBJECT_HANDLE handles[8];
    CK_ULONG n = 0;
    rv = C_FindObjects(ctx->session, handles, 8, &n);
    C_FindObjectsFinal(ctx->session);
    if (rv != CKR_OK) {
        return -1;
    }
    *count = n;
    return 0;
}

static int case_destroy(Ctx *ctx, Case *c) {
    if (!ctx->key_live) {
        return fail(c, "no key");
    }
    CK_RV rv = C_DestroyObject(ctx->session, ctx->key);
    if (rv != CKR_OK) {
        return fail(c, "C_DestroyObject failed: 0x%lx", rv);
    }
    ctx->key_live = 0;
    CK_ULONG n = 99;
    if (find_count(ctx, &n) != 0) {
        return fail(c, "search after destroy failed");
    }
    if (n != 0) {
        return fail(c, "label still resolves to %lu object(s)", n);
    }
    snprintf(c->message, sizeof(c->message), "label %s removed", ctx->label);
    return 0;
}

static long elapsed_ms(const struct timespec *start, const struct timespec *end) {
    return (long)(end->tv_sec - start->tv_sec) * 1000L
        + (long)(end->tv_nsec - start->tv_nsec) / 1000000L;
}

static void run_case(Case *c, Ctx *ctx, int (*fn)(Ctx *, Case *)) {
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = fn(ctx, c);
    clock_gettime(CLOCK_MONOTONIC, &end);
    c->duration_ms = elapsed_ms(&start, &end);
    if (rc != 0) {
        c->failed = 1;
    }
    printf("%s %s%s%s\n", c->failed ? "FAIL" : "PASS", c->id,
           c->message[0] ? " " : "", c->message);
}

static void xml_escape(FILE *out, const char *text) {
    for (const char *p = text; *p != '\0'; p++) {
        switch (*p) {
            case '&': fputs("&amp;", out); break;
            case '<': fputs("&lt;", out); break;
            case '>': fputs("&gt;", out); break;
            case '"': fputs("&quot;", out); break;
            default: fputc(*p, out); break;
        }
    }
}

static int write_junit(const char *path, Case *cases) {
    FILE *out = fopen(path, "w");
    if (out == NULL) {
        fprintf(stderr, "cannot write %s\n", path);
        return -1;
    }
    int failures = 0;
    for (int i = 0; i < CASE_COUNT; i++) {
        if (cases[i].failed) {
            failures++;
        }
    }
    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(out, "<testsuite name=\"pkcs11_campaign\" tests=\"%d\" failures=\"%d\">\n",
            CASE_COUNT, failures);
    for (int i = 0; i < CASE_COUNT; i++) {
        double seconds = (double)cases[i].duration_ms / 1000.0;
        fprintf(out, "  <testcase classname=\"native.pkcs11\" name=\"%s\" time=\"%.3f\">",
                cases[i].id, seconds);
        if (cases[i].failed) {
            fputs("<failure message=\"", out);
            xml_escape(out, cases[i].message);
            fputs("\">", out);
            xml_escape(out, cases[i].message);
            fputs("</failure>", out);
        }
        fputs("</testcase>\n", out);
    }
    fputs("</testsuite>\n", out);
    fclose(out);
    return 0;
}

int main(int argc, char **argv) {
    const char *junit_path = "c-junit.xml";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--junit") == 0 && i + 1 < argc) {
            junit_path = argv[++i];
        }
    }

    Case cases[CASE_COUNT] = {
        {.id = "REQ-C-004"},
        {.id = "REQ-C-001"},
        {.id = "REQ-C-002"},
        {.id = "REQ-C-003"},
        {.id = "REQ-C-005"},
    };
    Ctx ctx;
    memset(&ctx, 0, sizeof(ctx));

    const char *label = getenv("HSM_TOKEN_LABEL");
    if (label == NULL || label[0] == '\0') {
        label = "kms-token";
    }

    CK_C_INITIALIZE_ARGS args;
    memset(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    CK_RV rv = C_Initialize(&args);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        snprintf(ctx.error, sizeof(ctx.error), "C_Initialize failed: 0x%lx", rv);
    } else if (find_slot(&ctx, label) != 0) {
        /* ctx.error already set */
    }

    if (ctx.error[0] != '\0') {
        for (int i = 0; i < CASE_COUNT; i++) {
            cases[i].failed = 1;
            snprintf(cases[i].message, sizeof(cases[i].message), "%s", ctx.error);
            printf("FAIL %s %s\n", cases[i].id, cases[i].message);
        }
    } else {
        run_case(&cases[0], &ctx, case_wrong_pin);
        run_case(&cases[1], &ctx, case_login);
        run_case(&cases[2], &ctx, case_generate);
        run_case(&cases[3], &ctx, case_roundtrip);
        run_case(&cases[4], &ctx, case_destroy);
        if (ctx.key_live) {
            C_DestroyObject(ctx.session, ctx.key);
        }
        if (ctx.session_open) {
            C_Logout(ctx.session);
            C_CloseSession(ctx.session);
        }
    }

    C_Finalize(NULL);
    if (write_junit(junit_path, cases) != 0) {
        return 1;
    }
    for (int i = 0; i < CASE_COUNT; i++) {
        if (cases[i].failed) {
            return 1;
        }
    }
    return 0;
}
