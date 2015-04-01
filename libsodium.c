
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_libsodium.h"

#include <sodium.h>
#include <stdint.h>

const int pass_rest_by_reference = 1;
const int pass_arg_by_reference = 0;

ZEND_BEGIN_ARG_INFO_EX(AI_None, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_FirstArgByReferenceSecondLength, 0, 0, 2)
  ZEND_ARG_INFO(1, reference)
  ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_TwoStrings, 0, 0, 2)
  ZEND_ARG_INFO(0, string_1)
  ZEND_ARG_INFO(0, string_2)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_OneString, 0, 0, 1)
  ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndOptionalString, 0, 0, 1)
  ZEND_ARG_INFO(0, string_1)
  ZEND_ARG_INFO(0, string_2)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_Length, 0, 0, 1)
  ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_Integer, 0, 0, 1)
  ZEND_ARG_INFO(0, integer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndKey, 0, 0, 2)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_SignatureAndStringAndKey, 0, 0, 3)
  ZEND_ARG_INFO(0, signature)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_Key, 0, 0, 1)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_SecretKeyAndPublicKey, 0, 0, 2)
  ZEND_ARG_INFO(0, secret_key)
  ZEND_ARG_INFO(0, public_key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_LengthAndNonceAndKey, 0, 0, 3)
  ZEND_ARG_INFO(0, length)
  ZEND_ARG_INFO(0, nonce)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndNonceAndKey, 0, 0, 3)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, nonce)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndMaybeKeyAndLength, 0, 0, 1)
  ZEND_ARG_INFO(0, string)

  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_LengthAndPasswordAndSaltAndOpsLimitAndMemLimit, 0, 0, 5)
  ZEND_ARG_INFO(0, length)
  ZEND_ARG_INFO(0, password)
  ZEND_ARG_INFO(0, salt)
  ZEND_ARG_INFO(0, opslimit)
  ZEND_ARG_INFO(0, memlimit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_PasswordAndOpsLimitAndMemLimit, 0, 0, 3)
  ZEND_ARG_INFO(0, password)
  ZEND_ARG_INFO(0, opslimit)
  ZEND_ARG_INFO(0, memlimit)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_HashAndPassword, 0, 0, 2)
  ZEND_ARG_INFO(0, hash)
  ZEND_ARG_INFO(0, password)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndADAndNonceAndKey, 0, 0, 4)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, ad)
  ZEND_ARG_INFO(0, nonce)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

#ifndef PHP_FE_END
# define PHP_FE_END { NULL, NULL, NULL }
#endif

const zend_function_entry libsodium_methods[] = {
    PHP_ME(Sodium, crypto_aead_chacha20poly1305_decrypt, AI_StringAndADAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_aead_chacha20poly1305_encrypt, AI_StringAndADAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box, AI_StringAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_keypair, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_keypair_from_secretkey_and_publickey, AI_SecretKeyAndPublicKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_open, AI_StringAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_publickey, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_publickey_from_secretkey, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_box_secretkey, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_generichash, AI_StringAndMaybeKeyAndLength, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_pwhash_scryptsalsa208sha256, AI_LengthAndPasswordAndSaltAndOpsLimitAndMemLimit, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_pwhash_scryptsalsa208sha256_str, AI_PasswordAndOpsLimitAndMemLimit, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_pwhash_scryptsalsa208sha256_str_verify, AI_HashAndPassword, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_secretbox, AI_StringAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_secretbox_open, AI_StringAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_shorthash, AI_StringAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign, AI_StringAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_detached, AI_StringAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_keypair, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_keypair_from_secretkey_and_publickey, AI_SecretKeyAndPublicKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_open, AI_StringAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_verify_detached, AI_SignatureAndStringAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_publickey, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_secretkey, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_sign_seed_keypair, AI_Key, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_stream, AI_LengthAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, crypto_stream_xor, AI_StringAndNonceAndKey, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, randombytes_buf, AI_Length, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, randombytes_random16, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, randombytes_uniform, AI_Integer, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_library_version_major, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_library_version_minor, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_memcmp, AI_TwoStrings, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_memzero, AI_FirstArgByReferenceSecondLength, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_bin2hex, AI_OneString, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_hex2bin, AI_StringAndOptionalString, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(Sodium, sodium_version_string, AI_None, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

zend_module_entry libsodium_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "libsodium",
    NULL,
    PHP_MINIT(libsodium),
    PHP_MSHUTDOWN(libsodium),
    NULL,
    NULL,
    PHP_MINFO(libsodium),
#if ZEND_MODULE_API_NO >= 20010901
    PHP_LIBSODIUM_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_LIBSODIUM
ZEND_GET_MODULE(libsodium)
#endif

PHP_MINIT_FUNCTION(libsodium)
{
    zend_class_entry  class_entry;
    zend_class_entry *class_entry_i;

    if (sodium_init() != 0) {
        zend_error(E_ERROR, "sodium_init()");
    }
    INIT_CLASS_ENTRY(class_entry, "Sodium", libsodium_methods);
    class_entry_i = zend_register_internal_class(&class_entry TSRMLS_CC);

#define CLASS_CONSTANT_LONG(NAME, VALUE) \
    zend_declare_class_constant_long(class_entry_i, NAME, sizeof(NAME) - 1U, \
                                     (VALUE) TSRMLS_CC)

#define CLASS_CONSTANT_STRING(NAME, STR) \
    zend_declare_class_constant_string(class_entry_i, NAME, sizeof(NAME) - 1U, \
                                       STR TSRMLS_CC)

    CLASS_CONSTANT_LONG("CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES",
                        crypto_aead_chacha20poly1305_KEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES",
                        crypto_aead_chacha20poly1305_NSECBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES",
                        crypto_aead_chacha20poly1305_NPUBBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_AEAD_CHACHA20POLY1305_ABYTES",
                        crypto_aead_chacha20poly1305_ABYTES);
    CLASS_CONSTANT_LONG("CRYPTO_BOX_SECRETKEYBYTES",
                        crypto_box_SECRETKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_BOX_PUBLICKEYBYTES",
                        crypto_box_PUBLICKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_BOX_KEYPAIRBYTES",
                        crypto_box_SECRETKEYBYTES +
                        crypto_box_PUBLICKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_BOX_NONCEBYTES",
                        crypto_box_NONCEBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_BYTES",
                        crypto_generichash_BYTES);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_BYTES_MIN",
                        crypto_generichash_BYTES_MIN);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_BYTES_MAX",
                        crypto_generichash_BYTES_MAX);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_KEYBYTES",
                        crypto_generichash_KEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_KEYBYTES_MIN",
                        crypto_generichash_KEYBYTES_MIN);
    CLASS_CONSTANT_LONG("CRYPTO_GENERICHASH_KEYBYTES_MAX",
                        crypto_generichash_KEYBYTES_MAX);
    CLASS_CONSTANT_LONG("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES",
                        crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
#ifndef crypto_pwhash_scryptsalsa208sha256_STRPREFIX
# define crypto_pwhash_scryptsalsa208sha256_STRPREFIX "$7$"
#endif
    CLASS_CONSTANT_STRING("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX",
                          crypto_pwhash_scryptsalsa208sha256_STRPREFIX);
    CLASS_CONSTANT_LONG("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE",
                        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
    CLASS_CONSTANT_LONG("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE",
                        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    CLASS_CONSTANT_LONG("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE",
                        crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
    CLASS_CONSTANT_LONG("CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE",
                        crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
    CLASS_CONSTANT_LONG("CRYPTO_SHORTHASH_BYTES",
                        crypto_shorthash_BYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SHORTHASH_KEYBYTES",
                        crypto_shorthash_KEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SECRETBOX_KEYBYTES",
                        crypto_secretbox_KEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SECRETBOX_NONCEBYTES",
                        crypto_secretbox_NONCEBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SIGN_BYTES",
                        crypto_sign_BYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SIGN_SEEDBYTES",
                        crypto_sign_SEEDBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SIGN_PUBLICKEYBYTES",
                        crypto_sign_PUBLICKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SIGN_SECRETKEYBYTES",
                        crypto_sign_SECRETKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_SIGN_KEYPAIRBYTES",
                        crypto_sign_SECRETKEYBYTES +
                        crypto_sign_PUBLICKEYBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_STREAM_NONCEBYTES",
                        crypto_stream_NONCEBYTES);
    CLASS_CONSTANT_LONG("CRYPTO_STREAM_KEYBYTES",
                        crypto_stream_KEYBYTES);
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(libsodium)
{
    return SUCCESS;
}

PHP_MINFO_FUNCTION(libsodium)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "libsodium support", "enabled");
    php_info_print_table_end();
}

PHP_METHOD(Sodium, sodium_version_string)
{
    RETURN_STRING(sodium_version_string(), 1);
}

PHP_METHOD(Sodium, sodium_library_version_major)
{
    RETURN_LONG(sodium_library_version_major());
}

PHP_METHOD(Sodium, sodium_library_version_minor)
{
    RETURN_LONG(sodium_library_version_minor());
}

PHP_METHOD(Sodium, sodium_memzero)
{
    zval *zv;
    char *buf;
    int   len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                              "z", &zv) == FAILURE ||
        Z_TYPE_P(zv) != IS_STRING) {
        zend_error(E_ERROR, "sodium_memzero: a PHP string is required");
    }
    buf = Z_STRVAL(*zv);
    len = Z_STRLEN(*zv);
    if (len > 0) {
        sodium_memzero(buf, (size_t) len);
    }
    convert_to_null(zv);
}

PHP_METHOD(Sodium, sodium_memcmp)
{
    char *buf1;
    char *buf2;
    int   len1;
    int   len2;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &buf1, &len1,
                              &buf2, &len2) == FAILURE) {
        return;
    }
    if (len1 != len2) {
        RETURN_LONG(-1);
    } else if (len1 > SIZE_MAX) {
        zend_error(E_ERROR, "sodium_memcmp(): invalid length");
    } else {
        RETURN_LONG(sodium_memcmp(buf1, buf2, (size_t) len1));
    }
}

PHP_METHOD(Sodium, randombytes_buf)
{
    char *buf;
    long  len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &len) == FAILURE ||
        len <= 0 || len >= INT_MAX) {
        zend_error(E_ERROR, "randombytes_buf(): invalid length");
    }
    buf = safe_emalloc((size_t) len + 1U, 1U, 0U);
    randombytes_buf(buf, (size_t) len);
    buf[len] = 0U;

    RETURN_STRINGL(buf, (int) len, 0);
}

PHP_METHOD(Sodium, randombytes_random16)
{
    RETURN_LONG((long) (randombytes_random() & (uint32_t) 0xffff));
}

PHP_METHOD(Sodium, randombytes_uniform)
{
    long upper_bound;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &upper_bound) == FAILURE ||
        upper_bound <= 0 || upper_bound > INT32_MAX) {
        zend_error(E_ERROR, "randombytes_uniform(): invalid upper bound");
    }
    RETURN_LONG((long) randombytes_uniform((uint32_t) upper_bound));
}

PHP_METHOD(Sodium, crypto_shorthash)
{
    unsigned char *hash;
    unsigned char *key;
    unsigned char *msg;
    int            key_len;
    int            msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (key_len != crypto_shorthash_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_shorthash(): key size should be "
                   "CRYPTO_SHORTHASH_KEYBYTES bytes");
    }
    hash = safe_emalloc(crypto_shorthash_BYTES + 1U, 1U, 0U);
    if (crypto_shorthash(hash, msg, (unsigned long long) msg_len, key) != 0) {
        efree(hash);
        zend_error(E_ERROR, "crypto_shorthash()");
    }
    hash[crypto_shorthash_BYTES] = 0U;

    RETURN_STRINGL((char *) hash, crypto_shorthash_BYTES, 0);
}

PHP_METHOD(Sodium, crypto_secretbox)
{
    unsigned char *ciphertext;
    unsigned char *key;
    unsigned char *msg;
    unsigned char *nonce;
    int            key_len;
    int            msg_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox(): nonce size should be "
                   "CRYPTO_SECRETBOX_NONCEBYTES bytes");
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox(): key size should be "
                   "CRYPTO_SECRETBOX_KEYBYTES bytes");
    }
    if (INT_MAX - msg_len <= crypto_secretbox_MACBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    ciphertext = safe_emalloc((size_t) msg_len + crypto_secretbox_MACBYTES + 1U,
                              1U, 0U);
    if (crypto_secretbox_easy(ciphertext, msg, (unsigned long long) msg_len,
                              nonce, key) != 0) {
        efree(ciphertext);
        zend_error(E_ERROR, "crypto_secretbox()");
    }
    ciphertext[msg_len + crypto_secretbox_MACBYTES] = 0U;

    RETURN_STRINGL((char *) ciphertext, msg_len + crypto_secretbox_MACBYTES, 0);
}

PHP_METHOD(Sodium, crypto_secretbox_open)
{
    unsigned char *key;
    unsigned char *ciphertext;
    unsigned char *msg;
    unsigned char *nonce;
    int            key_len;
    int            ciphertext_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): nonce size should be "
                   "CRYPTO_SECRETBOX_NONCEBYTES bytes");
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): key size should be "
                   "CRYPTO_SECRETBOX_KEYBYTES bytes");
    }
    if (ciphertext_len < crypto_secretbox_MACBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): short ciphertext");
    }
    msg = safe_emalloc((size_t) ciphertext_len - crypto_secretbox_MACBYTES + 1U,
                       1U, 0U);
    if (crypto_secretbox_open_easy(msg, ciphertext,
                                   (unsigned long long) ciphertext_len,
                                   nonce, key) != 0) {
        efree(msg);
        RETURN_FALSE;
    } else {
        msg[ciphertext_len - crypto_secretbox_MACBYTES] = 0U;
        RETURN_STRINGL((char *) msg,
                       ciphertext_len - crypto_secretbox_MACBYTES, 0);
    }
}

PHP_METHOD(Sodium, crypto_generichash)
{
    unsigned char *hash;
    unsigned char *key = NULL;
    unsigned char *msg;
    long           hash_len = crypto_generichash_BYTES;
    int            key_len = 0;
    int            msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sl",
                              &msg, &msg_len,
                              &key, &key_len,
                              &hash_len) == FAILURE) {
        return;
    }
    if (hash_len < crypto_generichash_BYTES_MIN ||
        hash_len > crypto_generichash_BYTES_MAX) {
        zend_error(E_ERROR, "crypto_generichash(): unsupported output length");
    }
    if (key_len != 0 &&
        (key_len < crypto_generichash_KEYBYTES_MIN ||
         key_len > crypto_generichash_KEYBYTES_MAX)) {
        zend_error(E_ERROR, "crypto_generichash(): unsupported key length");
    }
    hash = safe_emalloc((size_t) hash_len + 1U, 1U, 0U);
    if (crypto_generichash(hash, (size_t) hash_len,
                           msg, (unsigned long long) msg_len,
                           key, (size_t) key_len) != 0) {
        efree(hash);
        zend_error(E_ERROR, "crypto_generichash()");
    }
    hash[hash_len] = 0U;

    RETURN_STRINGL((char *) hash, (int) hash_len, 0);
}

PHP_METHOD(Sodium, crypto_box_keypair)
{
    unsigned char *keypair;
    size_t         keypair_len;

    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len + 1U, 1U, 0U);
    if (crypto_box_keypair(keypair + crypto_box_SECRETKEYBYTES,
                           keypair) != 0) {
        efree(keypair);
        zend_error(E_ERROR, "crypto_box_keypair()");
    }
    keypair[keypair_len] = 0U;

    RETURN_STRINGL((char *) keypair, (int) keypair_len, 0);
}

PHP_METHOD(Sodium, crypto_box_keypair_from_secretkey_and_publickey)
{
    char   *keypair;
    char   *publickey;
    char   *secretkey;
    size_t  keypair_len;
    int     publickey_len;
    int     secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &secretkey, &secretkey_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_box_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_keypair_from_secretkey_and_publickey(): "
                   "secretkey should be CRYPTO_BOX_SECRETKEYBYTES long");
    }
    if (publickey_len != crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_keypair_from_secretkey_and_publickey(): "
                   "publickey should be CRYPTO_BOX_PUBLICKEYBYTES long");
    }
    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len + 1U, 1U, 0U);
    memcpy(keypair, secretkey, crypto_box_SECRETKEYBYTES);
    memcpy(keypair + crypto_box_SECRETKEYBYTES, publickey,
           crypto_box_PUBLICKEYBYTES);
    keypair[keypair_len] = 0U;

    RETURN_STRINGL(keypair, (int) keypair_len, 0);
}

PHP_METHOD(Sodium, crypto_box_secretkey)
{
    unsigned char *keypair;
    char          *secretkey;
    int            keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_secretkey(): keypair should be "
                   "CRYPTO_BOX_KEYPAIRBYTES long");
    }
    secretkey = safe_emalloc(crypto_box_SECRETKEYBYTES + 1U, 1U, 0U);
    memcpy(secretkey, keypair, crypto_box_SECRETKEYBYTES);
    secretkey[crypto_box_SECRETKEYBYTES] = 0U;

    RETURN_STRINGL((char *) secretkey, crypto_box_SECRETKEYBYTES, 0);
}

PHP_METHOD(Sodium, crypto_box_publickey)
{
    unsigned char *keypair;
    char          *publickey;
    int            keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_publickey(): keypair should be "
                   "CRYPTO_BOX_KEYPAIRBYTES long");
    }
    publickey = safe_emalloc(crypto_box_PUBLICKEYBYTES + 1U, 1U, 0U);
    memcpy(publickey, keypair + crypto_box_SECRETKEYBYTES,
           crypto_box_PUBLICKEYBYTES);
    publickey[crypto_box_PUBLICKEYBYTES] = 0U;

    RETURN_STRINGL((char *) publickey, crypto_box_PUBLICKEYBYTES, 0);
}

PHP_METHOD(Sodium, crypto_box_publickey_from_secretkey)
{
    unsigned char *publickey;
    unsigned char *secretkey;
    int            secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_box_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_publickey_from_secretkey(): key should be "
                   "CRYPTO_BOX_SECRETKEYBYTES long");
    }
    publickey = safe_emalloc(crypto_box_PUBLICKEYBYTES + 1U, 1U, 0U);
    (void) sizeof(int[crypto_scalarmult_BYTES ==
                      crypto_box_PUBLICKEYBYTES ? 1 : -1]);
    (void) sizeof(int[crypto_scalarmult_SCALARBYTES ==
                      crypto_box_SECRETKEYBYTES ? 1 : -1]);
    crypto_scalarmult_base(publickey, secretkey);
    publickey[crypto_box_PUBLICKEYBYTES] = 0U;

    RETURN_STRINGL((char *) publickey, crypto_box_PUBLICKEYBYTES, 0);
}

PHP_METHOD(Sodium, crypto_box)
{
    unsigned char *ciphertext;
    unsigned char *keypair;
    unsigned char *msg;
    unsigned char *nonce;
    unsigned char *publickey;
    unsigned char *secretkey;
    int            keypair_len;
    int            msg_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_box(): nonce size should be "
                   "CRYPTO_BOX_NONCEBYTES bytes");
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box(): keypair size should be "
                   "CRYPTO_BOX_KEYPAIRBYTES bytes");
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (INT_MAX - msg_len <= crypto_box_MACBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    ciphertext = safe_emalloc((size_t) msg_len + crypto_box_MACBYTES + 1U, 1U, 0U);
    if (crypto_box_easy(ciphertext, msg, (unsigned long long) msg_len,
                        nonce, publickey, secretkey) != 0) {
        efree(ciphertext);
        zend_error(E_ERROR, "crypto_box()");
    }
    ciphertext[msg_len + crypto_box_MACBYTES] = 0U;

    RETURN_STRINGL((char *) ciphertext, msg_len + crypto_box_MACBYTES, 0);
}

PHP_METHOD(Sodium, crypto_box_open)
{
    unsigned char *ciphertext;
    unsigned char *keypair;
    unsigned char *msg;
    unsigned char *nonce;
    unsigned char *publickey;
    unsigned char *secretkey;
    int            ciphertext_len;
    int            keypair_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): nonce size should be "
                   "CRYPTO_BOX_NONCEBYTES bytes");
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): keypair size should be "
                   "CRYPTO_BOX_KEYBYTES bytes");
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (ciphertext_len < crypto_box_MACBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): short ciphertext");
    }
    msg = safe_emalloc((size_t) ciphertext_len - crypto_box_MACBYTES + 1U,
                       1U, 0U);
    if (crypto_box_open_easy(msg, ciphertext,
                             (unsigned long long) ciphertext_len,
                             nonce, publickey, secretkey) != 0) {
        efree(msg);
        RETURN_FALSE;
    } else {
        msg[ciphertext_len - crypto_box_MACBYTES] = 0U;
        RETURN_STRINGL((char *) msg,
                       ciphertext_len - crypto_box_MACBYTES, 0);
    }
}

PHP_METHOD(Sodium, crypto_sign_keypair)
{
    unsigned char *keypair;
    size_t         keypair_len;

    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len + 1U, 1U, 0U);
    if (crypto_sign_keypair(keypair + crypto_sign_SECRETKEYBYTES,
                            keypair) != 0) {
        efree(keypair);
        zend_error(E_ERROR, "crypto_sign_keypair()");
    }
    keypair[keypair_len] = 0U;

    RETURN_STRINGL((char *) keypair, keypair_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_seed_keypair)
{
    unsigned char *keypair;
    unsigned char *seed;
    size_t         keypair_len;
    int            seed_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &seed, &seed_len) == FAILURE) {
        return;
    }
    if (seed_len != crypto_sign_SEEDBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_seed_keypair(): "
                   "seed should be crypto_sign_SEEDBYTES long");
    }
    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len + 1U, 1U, 0U);
    if (crypto_sign_seed_keypair(keypair + crypto_sign_SECRETKEYBYTES,
                                 keypair, seed) != 0) {
        efree(keypair);
        zend_error(E_ERROR, "crypto_sign_seed_keypair()");
    }
    keypair[keypair_len] = 0U;

    RETURN_STRINGL((char *) keypair, keypair_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_keypair_from_secretkey_and_publickey)
{
    char   *keypair;
    char   *publickey;
    char   *secretkey;
    size_t  keypair_len;
    int     publickey_len;
    int     secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &secretkey, &secretkey_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_keypair_from_secretkey_and_publickey(): "
                   "secretkey should be CRYPTO_SIGN_SECRETKEYBYTES long");
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_keypair_from_secretkey_and_publickey(): "
                   "publickey should be CRYPTO_SIGN_PUBLICKEYBYTES long");
    }
    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len + 1U, 1U, 0U);
    memcpy(keypair, secretkey, crypto_sign_SECRETKEYBYTES);
    memcpy(keypair + crypto_sign_SECRETKEYBYTES, publickey,
           crypto_sign_PUBLICKEYBYTES);
    keypair[keypair_len] = 0U;

    RETURN_STRINGL(keypair, keypair_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_secretkey)
{
    unsigned char *keypair;
    char          *secretkey;
    int            keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_secretkey(): keypair should be "
                   "CRYPTO_SIGN_KEYPAIRBYTES long");
    }
    secretkey = safe_emalloc(crypto_sign_SECRETKEYBYTES + 1U, 1U, 0U);
    memcpy(secretkey, keypair, crypto_sign_SECRETKEYBYTES);
    secretkey[crypto_sign_SECRETKEYBYTES] = 0U;

    RETURN_STRINGL((char *) secretkey, crypto_sign_SECRETKEYBYTES, 0);
}

PHP_METHOD(Sodium, crypto_sign_publickey)
{
    unsigned char *keypair;
    char          *publickey;
    int            keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_publickey(): keypair should be "
                   "CRYPTO_SIGN_KEYPAIRBYTES long");
    }
    publickey = safe_emalloc(crypto_sign_PUBLICKEYBYTES + 1U, 1U, 0U);
    memcpy(publickey, keypair + crypto_sign_SECRETKEYBYTES,
           crypto_sign_PUBLICKEYBYTES);
    publickey[crypto_sign_PUBLICKEYBYTES] = 0U;

    RETURN_STRINGL((char *) publickey, crypto_sign_PUBLICKEYBYTES, 0);
}

PHP_METHOD(Sodium, crypto_sign)
{
    unsigned char      *msg;
    unsigned char      *msg_signed;
    unsigned char      *secretkey;
    unsigned long long  msg_signed_real_len;
    int                 msg_len;
    int                 msg_signed_len;
    int                 secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign(): secret key size should be "
                   "CRYPTO_SIGN_SECRETKEYBYTES bytes");
    }
    if (INT_MAX - msg_len <= crypto_sign_BYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg_signed_len = msg_len + crypto_sign_BYTES;
    msg_signed = safe_emalloc((size_t) msg_signed_len + 1U, 1U, 0U);
    if (crypto_sign(msg_signed, &msg_signed_real_len, msg,
                    (unsigned long long) msg_len, secretkey) != 0) {
        efree(msg_signed);
        zend_error(E_ERROR, "crypto_sign()");
    }
    if (msg_signed_real_len <= 0U || msg_signed_real_len >= INT_MAX ||
        msg_signed_real_len > msg_signed_len) {
        efree(msg_signed);
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg_signed[msg_signed_real_len] = 0U;

    RETURN_STRINGL((char *) msg_signed, (int) msg_signed_real_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_open)
{
    unsigned char      *msg;
    unsigned char      *msg_signed;
    unsigned char      *publickey;
    unsigned long long  msg_real_len;
    int                 msg_len;
    int                 msg_signed_len;
    int                 publickey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg_signed, &msg_signed_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_open(): public key size should be "
                   "CRYPTO_SIGN_PUBLICKEYBYTES bytes");
    }
    msg_len = msg_signed_len;
    if (msg_len >= INT_MAX) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg = safe_emalloc((size_t) msg_len + 1U, 1U, 0U);
    if (crypto_sign_open(msg, &msg_real_len, msg_signed,
                         (unsigned long long) msg_signed_len,
                         publickey) != 0) {
        sodium_memzero(msg, (size_t) msg_len);
        efree(msg);
        RETURN_FALSE;
    }
    if (msg_real_len >= INT_MAX || msg_real_len > msg_signed_len) {
        efree(msg);
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg[msg_real_len] = 0U;

    RETURN_STRINGL((char *) msg, (int) msg_real_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_detached)
{
    unsigned char      *msg;
    unsigned char      *signature;
    unsigned char      *secretkey;
    unsigned long long  signature_real_len;
    int                 msg_len;
    int                 secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_detached(): secret key size should be "
                   "CRYPTO_SIGN_SECRETKEYBYTES bytes");
    }
    signature = safe_emalloc((size_t) crypto_sign_BYTES + 1U, 1U, 0U);
    if (crypto_sign_detached(signature, &signature_real_len, msg,
                             (unsigned long long) msg_len, secretkey) != 0) {
        efree(signature);
        zend_error(E_ERROR, "crypto_sign_detached()");
    }
    if (signature_real_len <= 0U || signature_real_len > crypto_sign_BYTES) {
        efree(signature);
        zend_error(E_ERROR, "signature has a bogus size");
    }
    signature[signature_real_len] = 0U;

    RETURN_STRINGL((char *) signature, (int) signature_real_len, 0);
}

PHP_METHOD(Sodium, crypto_sign_verify_detached)
{
    unsigned char *msg;
    unsigned char *publickey;
    unsigned char *signature;
    int            msg_len;
    int            publickey_len;
    int            signature_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &signature, &signature_len,
                              &msg, &msg_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (signature_len != crypto_sign_BYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_verify_detached(): signature size should be "
                   "CRYPTO_SIGN_BYTES bytes");
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_sign_verify_detached(): public key size should be "
                   "CRYPTO_SIGN_PUBLICKEYBYTES bytes");
    }
    if (crypto_sign_verify_detached(signature,
                                    msg, (unsigned long long) msg_len,
                                    publickey) != 0) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(Sodium, crypto_stream)
{
    unsigned char *ciphertext;
    unsigned char *key;
    unsigned char *nonce;
    long           ciphertext_len;
    int            key_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lss",
                              &ciphertext_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (ciphertext_len <= 0 || ciphertext_len >= INT_MAX) {
        zend_error(E_ERROR, "crypto_stream(): invalid length");
    }
    if (nonce_len != crypto_stream_NONCEBYTES) {
        zend_error(E_ERROR, "nonce should be CRYPTO_STREAM_NONCEBYTES bytes");
    }
    if (key_len != crypto_stream_KEYBYTES) {
        zend_error(E_ERROR, "key should be CRYPTO_STREAM_KEYBYTES bytes");
    }
    ciphertext = safe_emalloc((size_t) ciphertext_len + 1U, 1U, 0U);
    if (crypto_stream(ciphertext, (unsigned long long) ciphertext_len, nonce,
                      key) != 0) {
        efree(ciphertext);
        zend_error(E_ERROR, "crypto_stream()");
    }
    ciphertext[ciphertext_len] = 0U;

    RETURN_STRINGL((char *) ciphertext, ciphertext_len, 0);
}

PHP_METHOD(Sodium, crypto_stream_xor)
{
    unsigned char *ciphertext;
    unsigned char *key;
    unsigned char *msg;
    unsigned char *nonce;
    int            key_len;
    int            msg_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_stream_NONCEBYTES) {
        zend_error(E_ERROR, "nonce should be CRYPTO_STREAM_NONCEBYTES bytes");
    }
    if (key_len != crypto_stream_KEYBYTES) {
        zend_error(E_ERROR, "key should be CRYPTO_STREAM_KEYBYTES bytes");
    }
    ciphertext = safe_emalloc((size_t) msg_len + 1U, 1U, 0U);
    if (crypto_stream_xor(ciphertext, msg, (unsigned long long) msg_len,
                          nonce, key) != 0) {
        efree(ciphertext);
        zend_error(E_ERROR, "crypto_stream_xor()");
    }
    ciphertext[msg_len] = 0U;

    RETURN_STRINGL((char *) ciphertext, msg_len, 0);
}

PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256)
{
    unsigned char *hash;
    unsigned char *salt;
    char          *passwd;
    long           hash_len;
    long           memlimit;
    long           opslimit;
    int            passwd_len;
    int            salt_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lssll",
                              &hash_len,
                              &passwd, &passwd_len,
                              &salt, &salt_len,
                              &opslimit, &memlimit) == FAILURE ||
        hash_len <= 0 || hash_len >= INT_MAX ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_error(E_ERROR, "crypto_pwhash_scryptsalsa208sha256(): invalid parameters");
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (salt_len != crypto_pwhash_scryptsalsa208sha256_SALTBYTES) {
        zend_error(E_ERROR,
                   "salt should be CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES bytes");
    }
    if (opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "number of operations for the scrypt function is low");
    }
    if (memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "maximum memory for the scrypt function is low");
    }
    hash = safe_emalloc((size_t) hash_len + 1U, 1U, 0U);
    if (crypto_pwhash_scryptsalsa208sha256
        (hash, (unsigned long long) hash_len,
         passwd, (unsigned long long) passwd_len, salt,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        efree(hash);
        zend_error(E_ERROR, "crypto_pwhash_scryptsalsa208sha256()");
    }
    hash[hash_len] = 0U;

    RETURN_STRINGL((char *) hash, hash_len, 0);
}

PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256_str)
{
    char *hash_str;
    char *passwd;
    long  memlimit;
    long  opslimit;
    int   passwd_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll",
                              &passwd, &passwd_len,
                              &opslimit, &memlimit) == FAILURE ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_error(E_ERROR,
                   "crypto_pwhash_scryptsalsa208sha256_str(): invalid parameters");
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (opslimit < crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "number of operations for the scrypt function is low");
    }
    if (memlimit < crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "maximum memory for the scrypt function is low");
    }
    hash_str = safe_emalloc(crypto_pwhash_scryptsalsa208sha256_STRBYTES + 1U,
                       1U, 0U);
    if (crypto_pwhash_scryptsalsa208sha256_str
        (hash_str, passwd, (unsigned long long) passwd_len,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        efree(hash_str);
        zend_error(E_ERROR, "crypto_pwhash_scryptsalsa208sha256_str()");
    }
    hash_str[crypto_pwhash_scryptsalsa208sha256_STRBYTES] = 0U;

    RETURN_STRINGL((char *) hash_str,
                   crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1, 0);
}

PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256_str_verify)
{
    char *hash_str;
    char *passwd;
    int   hash_str_len;
    int   passwd_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &hash_str, &hash_str_len,
                              &passwd, &passwd_len) == FAILURE) {
        zend_error(E_ERROR,
                   "crypto_pwhash_scryptsalsa208sha256_str_verify(): invalid parameters");
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (hash_str_len != crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1) {
        zend_error(E_WARNING, "wrong size for the hashed password");
        RETURN_FALSE;
    }
    if (crypto_pwhash_scryptsalsa208sha256_str_verify
        (hash_str, passwd, (unsigned long long) passwd_len) == 0) {
        RETURN_TRUE;
    }
    RETURN_FALSE;
}

PHP_METHOD(Sodium, crypto_aead_chacha20poly1305_encrypt)
{
    unsigned char      *ad;
    unsigned char      *ciphertext;
    unsigned char      *msg;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  ciphertext_real_len;
    int                 ad_len;
    int                 ciphertext_len;
    int                 msg_len;
    int                 npub_len;
    int                 secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &msg, &msg_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        zend_error(E_ERROR,
                   "crypto_aead_chacha20poly1305_encrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes");
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_aead_chacha20poly1305_encrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes");
    }
    if (INT_MAX - msg_len <= crypto_aead_chacha20poly1305_ABYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    ciphertext_len = msg_len + crypto_aead_chacha20poly1305_ABYTES;
    ciphertext = safe_emalloc((size_t) ciphertext_len + 1U, 1U, 0U);
    if (crypto_aead_chacha20poly1305_encrypt
        (ciphertext, &ciphertext_real_len, msg, (unsigned long long) msg_len,
         ad, (unsigned long long) ad_len, NULL, npub, secretkey) != 0) {
        efree(ciphertext);
        zend_error(E_ERROR, "crypto_aead_chacha20poly1305_encrypt()");
    }
    if (ciphertext_real_len <= 0U || ciphertext_real_len >= INT_MAX ||
        ciphertext_real_len > ciphertext_len) {
        efree(ciphertext);
        zend_error(E_ERROR, "arithmetic overflow");
    }
    ciphertext[ciphertext_real_len] = 0U;

    RETURN_STRINGL((char *) ciphertext, (int) ciphertext_real_len, 0);
}

PHP_METHOD(Sodium, crypto_aead_chacha20poly1305_decrypt)
{
    unsigned char      *ad;
    unsigned char      *ciphertext;
    unsigned char      *msg;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  msg_real_len;
    int                 ad_len;
    int                 ciphertext_len;
    int                 msg_len;
    int                 npub_len;
    int                 secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &ciphertext, &ciphertext_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        zend_error(E_ERROR,
                   "crypto_aead_chacha20poly1305_decrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes");
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_aead_chacha20poly1305_decrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes");
    }
    msg_len = ciphertext_len;
    if (msg_len >= INT_MAX) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg = safe_emalloc((size_t) msg_len + 1U, 1U, 0U);
    if (crypto_aead_chacha20poly1305_decrypt
        (msg, &msg_real_len, NULL,
         ciphertext, (unsigned long long) ciphertext_len,
         ad, (unsigned long long) ad_len, npub, secretkey) != 0) {
        efree(msg);
        zend_error(E_ERROR, "crypto_aead_chacha20poly1305_decrypt()");
    }
    if (msg_real_len >= INT_MAX || msg_real_len > msg_len) {
        efree(msg);
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg[msg_real_len] = 0U;

    RETURN_STRINGL((char *) msg, (int) msg_real_len, 0);
}

PHP_METHOD(Sodium, sodium_bin2hex)
{
    unsigned char      *binstring;
    int                binstring_len;
    unsigned char      *hexstring;
    int                hexstring_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &binstring, &binstring_len) == FAILURE) {
        return;
    }

    if (sodium_bin2hex(hexstring, (size_t) hexstring_len,
                       binstring, (size_t) binstring_len) != 0) {
        zend_error(E_ERROR, "sodium_bin2hex()");
    }
    hexstring[hexstring_len] = 0U;

    RETURN_STRINGL((char *) hexstring, (int) hexstring_len, 0);
}

PHP_METHOD(Sodium, sodium_hex2bin)
{
    unsigned char      *hexstring;
    int                hexstring_len;
    unsigned char      *ignore;
    int                ignore_len;

    unsigned char      *binstring;
    int                binstring_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s",
                              &hexstring, &hexstring_len,
                              &ignore, &ignore_len) == FAILURE) {
        return;
    }

    const char        *hexend = hexstring[hexstring_len - 1];

    if (sodium_hex2bin(binstring, (size_t) binstring_len,
                       hexstring, (size_t) hexstring_len,
                       ignore, (size_t) ignore_len,
                       (char**) hexend) != 0) {
        zend_error(E_ERROR, "sodium_bin2hex()");
    }
    binstring[binstring_len] = 0U;

    RETURN_STRINGL((char *) binstring, (int) binstring_len, 0);
}
