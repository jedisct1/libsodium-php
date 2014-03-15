
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_libsodium.h"

#include <sodium.h>
#include <stdint.h>

#ifndef crypto_secretbox_MACBYTES
# define crypto_secretbox_MACBYTES \
    (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)
#endif

const int pass_rest_by_reference = 1;
const int pass_arg_by_reference = 0;

ZEND_BEGIN_ARG_INFO(FirstArgByReference, 0)
ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()

#ifndef PHP_FE_END
# define PHP_FE_END { NULL, NULL, NULL }
#endif

const zend_function_entry libsodium_functions[] = {
    PHP_FE(sodium_version_string, NULL)
    PHP_FE(sodium_library_version_major, NULL)
    PHP_FE(sodium_library_version_minor, NULL)
    PHP_FE(sodium_memzero, FirstArgByReference)
    PHP_FE(sodium_memcmp, NULL)
    PHP_FE(randombytes_buf, NULL)
    PHP_FE(randombytes_random16, NULL)
    PHP_FE(randombytes_uniform, NULL)
    PHP_FE(crypto_shorthash, NULL)
    PHP_FE(crypto_secretbox, NULL)
    PHP_FE(crypto_secretbox_open, NULL)
    PHP_FE(crypto_generichash, NULL)
    PHP_FE(crypto_box_keypair, NULL)
    PHP_FE(crypto_box_keypair_from_secretkey_and_publickey, NULL)
    PHP_FE(crypto_box_secretkey, NULL)
    PHP_FE(crypto_box_publickey, NULL)
    PHP_FE(crypto_box_publickey_from_secretkey, NULL)
    PHP_FE(crypto_box, NULL)
    PHP_FE(crypto_box_open, NULL)
    PHP_FE_END
};

zend_module_entry libsodium_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    "libsodium",
    libsodium_functions,
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
    if (sodium_init() != 0) {
        zend_error(E_ERROR, "sodium_init()");
    }
    REGISTER_LONG_CONSTANT("CRYPTO_SHORTHASH_BYTES",
                           crypto_shorthash_BYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_SHORTHASH_KEYBYTES",
                           crypto_shorthash_KEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_SECRETBOX_KEYBYTES",
                           crypto_secretbox_KEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_SECRETBOX_NONCEBYTES",
                           crypto_secretbox_NONCEBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_BYTES",
                           crypto_generichash_BYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_BYTES_MIN",
                           crypto_generichash_BYTES_MIN,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_BYTES_MAX",
                           crypto_generichash_BYTES_MAX,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_KEYBYTES",
                           crypto_generichash_KEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_KEYBYTES_MIN",
                           crypto_generichash_KEYBYTES_MIN,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_KEYBYTES_MAX",
                           crypto_generichash_KEYBYTES_MAX,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_GENERICHASH_BLOCKBYTES",
                           crypto_generichash_BLOCKBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_BOX_SECRETKEYBYTES",
                           crypto_box_SECRETKEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_BOX_PUBLICKEYBYTES",
                           crypto_box_PUBLICKEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_BOX_KEYPAIRBYTES",
                           crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES,
                           CONST_PERSISTENT | CONST_CS);
    REGISTER_LONG_CONSTANT("CRYPTO_BOX_NONCEBYTES",
                           crypto_box_NONCEBYTES,
                           CONST_PERSISTENT | CONST_CS);
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

PHP_FUNCTION(sodium_version_string)
{
    RETURN_STRING(sodium_version_string(), 1);
}

PHP_FUNCTION(sodium_library_version_major)
{
    RETURN_LONG(sodium_library_version_major());
}

PHP_FUNCTION(sodium_library_version_minor)
{
    RETURN_LONG(sodium_library_version_minor());
}

PHP_FUNCTION(sodium_memzero)
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

PHP_FUNCTION(sodium_memcmp)
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
        RETURN_LONG(sodium_memcmp(buf1, buf2, len1));
    }
}

PHP_FUNCTION(randombytes_buf)
{
    char *buf;
    long  len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &len) == FAILURE ||
        len <= 0 || len > SIZE_MAX) {
        zend_error(E_ERROR, "randombytes_buf(): invalid length");
    }
    buf = safe_emalloc((size_t) len, 1U, 0U);
    randombytes_buf(buf, (size_t) len);

    RETURN_STRINGL(buf, len, 0);
}

PHP_FUNCTION(randombytes_random16)
{
    RETURN_LONG((long) (randombytes_random() & (uint32_t) 0xffff));
}

PHP_FUNCTION(randombytes_uniform)
{
    long upper_bound;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &upper_bound) == FAILURE ||
        upper_bound <= 0 || upper_bound > INT32_MAX) {
        zend_error(E_ERROR, "randombytes_uniform(): invalid upper bound");
    }
    RETURN_LONG((long) randombytes_uniform((uint32_t) upper_bound));
}

PHP_FUNCTION(crypto_shorthash)
{
    unsigned char *key;
    unsigned char *msg;
    unsigned char *out;
    int            key_len;
    int            msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (key_len != crypto_shorthash_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_shorthash(): key size should be CRYPTO_SHORTHASH_KEYBYTES long");
    }
    out = safe_emalloc(crypto_shorthash_BYTES, 1U, 0U);
    if (crypto_shorthash(out, msg, (unsigned long long) msg_len, key) != 0) {
        zend_error(E_ERROR, "crypto_shorthash()");
    }
    RETURN_STRINGL((char *) out, crypto_shorthash_BYTES, 0);
}

PHP_FUNCTION(crypto_secretbox)
{
    unsigned char *key;
    unsigned char *msg;
    unsigned char *msg_zeroed;
    unsigned char *nonce;
    unsigned char *out;
    int            key_len;
    int            msg_len;
    int            msg_zeroed_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox(): nonce size should be CRYPTO_SECRETBOX_NONCEBYTES long");
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox(): key size should be CRYPTO_SECRETBOX_KEYBYTES long");
    }
    if (INT_MAX - msg_len < crypto_secretbox_ZEROBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg_zeroed_len = msg_len + crypto_secretbox_ZEROBYTES;
    msg_zeroed = safe_emalloc((size_t) msg_zeroed_len, 1U, 0U);
    memset(msg_zeroed, 0, crypto_secretbox_ZEROBYTES);
    memcpy(msg_zeroed + crypto_secretbox_ZEROBYTES, msg, msg_len);
    if (INT_MAX - msg_len < crypto_secretbox_BOXZEROBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    out = safe_emalloc((size_t) msg_len + crypto_secretbox_ZEROBYTES, 1U, 0U);
    if (crypto_secretbox(out, msg_zeroed, (unsigned long long) msg_zeroed_len,
                         nonce, key) != 0) {
        zend_error(E_ERROR, "crypto_secretbox()");
    }
    efree(msg_zeroed);
    memmove(out, out + crypto_secretbox_MACBYTES,
            (size_t) msg_len + crypto_secretbox_MACBYTES);

    RETURN_STRINGL((char *) out,
                   (size_t) msg_len + crypto_secretbox_MACBYTES, 0);
}

PHP_FUNCTION(crypto_secretbox_open)
{
    unsigned char *key;
    unsigned char *ciphertext;
    unsigned char *ciphertext_boxed;
    unsigned char *nonce;
    unsigned char *out;
    int            key_len;
    int            ciphertext_len;
    int            ciphertext_boxed_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): nonce size should be CRYPTO_SECRETBOX_NONCEBYTES long");
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): key size should be CRYPTO_SECRETBOX_KEYBYTES long");
    }
    if (ciphertext_len < crypto_secretbox_MACBYTES) {
        zend_error(E_ERROR,
                   "crypto_secretbox_open(): short ciphertext");
    }
    ciphertext_boxed_len = ciphertext_len + crypto_secretbox_BOXZEROBYTES;
    ciphertext_boxed = safe_emalloc((size_t) ciphertext_boxed_len, 1U, 0U);
    memset(ciphertext_boxed, 0, crypto_secretbox_BOXZEROBYTES);
    memcpy(ciphertext_boxed + crypto_secretbox_BOXZEROBYTES, ciphertext, ciphertext_len);
    out = safe_emalloc((size_t) ciphertext_boxed_len +
                       crypto_secretbox_MACBYTES, 1U, 0U);
    if (crypto_secretbox_open(out, ciphertext_boxed,
                              (unsigned long long) ciphertext_boxed_len,
                              nonce, key) != 0) {
        RETVAL_FALSE;
    } else {
        RETVAL_STRINGL((char *) out + crypto_secretbox_ZEROBYTES,
                       ciphertext_len - crypto_secretbox_MACBYTES, 1);
    }
    efree(out);
}

PHP_FUNCTION(crypto_generichash)
{
    unsigned char *key = NULL;
    unsigned char *msg;
    unsigned char *out;
    long           out_len = crypto_generichash_BYTES;
    int            key_len = 0;
    int            msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sl",
                              &msg, &msg_len,
                              &key, &key_len,
                              &out_len) == FAILURE) {
        return;
    }
    if (out_len < crypto_generichash_BYTES_MIN ||
        out_len > crypto_generichash_BYTES_MAX) {
        zend_error(E_ERROR, "crypto_generichash(): unsupported output length");
    }
    if (key_len != 0 &&
        (key_len < crypto_generichash_KEYBYTES_MIN ||
         key_len > crypto_generichash_KEYBYTES_MAX)) {
        zend_error(E_ERROR, "crypto_generichash(): unsupported key length");
    }
    out = safe_emalloc((size_t) out_len, 1U, 0U);
    if (crypto_generichash(out, out_len, msg, msg_len, key, key_len) != 0) {
        zend_error(E_ERROR, "crypto_generichash()");
    }
    RETURN_STRINGL((char *) out, out_len, 0);
}

PHP_FUNCTION(crypto_box_keypair)
{
    unsigned char *keypair;
    size_t         keypair_len;

    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len, 1U, 0U);
    if (crypto_box_keypair(keypair + crypto_box_SECRETKEYBYTES,
                           keypair) != 0) {
        zend_error(E_ERROR, "crypto_box_keypair()");
    }
    RETURN_STRINGL((char *) keypair, keypair_len, 0);
}

PHP_FUNCTION(crypto_box_keypair_from_secretkey_and_publickey)
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
                   "crypto_box_keypair_from_secretkey_and_publickey(): secretkey should be CRYPTO_BOX_SECRETKEYBYTES long");
    }
    if (publickey_len != crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_keypair_from_secretkey_and_publickey(): publickey should be CRYPTO_BOX_PUBLICKEYBYTES long");
    }
    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = safe_emalloc(keypair_len, 1U, 0U);
    memcpy(keypair, secretkey, crypto_box_SECRETKEYBYTES);
    memcpy(keypair + crypto_box_SECRETKEYBYTES, publickey,
           crypto_box_PUBLICKEYBYTES);

    RETURN_STRINGL(keypair, keypair_len, 0);
}

PHP_FUNCTION(crypto_box_secretkey)
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
                   "crypto_box_secretkey(): keypair should be CRYPTO_BOX_KEYPAIRBYTES long");
    }
    secretkey = safe_emalloc(crypto_box_SECRETKEYBYTES, 1U, 0U);
    memcpy(secretkey, keypair, crypto_box_SECRETKEYBYTES);

    RETURN_STRINGL((char *) secretkey, crypto_box_SECRETKEYBYTES, 0);
}

PHP_FUNCTION(crypto_box_publickey)
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
                   "crypto_box_publickey(): keypair should be CRYPTO_BOX_KEYPAIRBYTES long");
    }
    publickey = safe_emalloc(crypto_box_PUBLICKEYBYTES, 1U, 0U);
    memcpy(publickey, keypair + crypto_box_SECRETKEYBYTES,
           crypto_box_PUBLICKEYBYTES);

    RETURN_STRINGL((char *) publickey, crypto_box_PUBLICKEYBYTES, 0);
}

PHP_FUNCTION(crypto_box_publickey_from_secretkey)
{
    unsigned char *secretkey;
    unsigned char *publickey;
    int            secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_box_SECRETKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_publickey_from_secretkey(): key should be CRYPTO_BOX_SECRETKEYBYTES long");
    }
    publickey = safe_emalloc(crypto_box_PUBLICKEYBYTES, 1U, 0U);
    (void) sizeof(int[crypto_scalarmult_BYTES ==
                      crypto_box_PUBLICKEYBYTES ? 1 : -1]);
    (void) sizeof(int[crypto_scalarmult_SCALARBYTES ==
                      crypto_box_SECRETKEYBYTES ? 1 : -1]);
    crypto_scalarmult_base(publickey, secretkey);

    RETURN_STRINGL((char *) publickey, crypto_box_PUBLICKEYBYTES, 0);
}

PHP_FUNCTION(crypto_box)
{
    unsigned char *keypair;
    unsigned char *msg;
    unsigned char *msg_zeroed;
    unsigned char *nonce;
    unsigned char *out;
    unsigned char *publickey;
    unsigned char *secretkey;
    int            keypair_len;
    int            msg_len;
    int            msg_zeroed_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_box(): nonce size should be CRYPTO_BOX_NONCEBYTES long");
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box(): keypair size should be CRYPTO_BOX_KEYPAIRBYTES long");
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (INT_MAX - msg_len < crypto_box_ZEROBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    msg_zeroed_len = msg_len + crypto_box_ZEROBYTES;
    msg_zeroed = safe_emalloc((size_t) msg_zeroed_len, 1U, 0U);
    memset(msg_zeroed, 0, crypto_box_ZEROBYTES);
    memcpy(msg_zeroed + crypto_box_ZEROBYTES, msg, msg_len);
    if (INT_MAX - msg_len < crypto_box_BOXZEROBYTES) {
        zend_error(E_ERROR, "arithmetic overflow");
    }
    out = safe_emalloc((size_t) msg_len + crypto_box_ZEROBYTES, 1U, 0U);
    if (crypto_box(out, msg_zeroed, (unsigned long long) msg_zeroed_len,
                   nonce, publickey, secretkey) != 0) {
        zend_error(E_ERROR, "crypto_box()");
    }
    efree(msg_zeroed);
    memmove(out, out + crypto_box_MACBYTES,
            (size_t) msg_len + crypto_box_MACBYTES);

    RETURN_STRINGL((char *) out,
                   (size_t) msg_len + crypto_box_MACBYTES, 0);
}

PHP_FUNCTION(crypto_box_open)
{
    unsigned char *keypair;
    unsigned char *ciphertext;
    unsigned char *ciphertext_boxed;
    unsigned char *nonce;
    unsigned char *out;
    unsigned char *publickey;
    unsigned char *secretkey;
    int            keypair_len;
    int            ciphertext_len;
    int            ciphertext_boxed_len;
    int            nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): nonce size should be CRYPTO_BOX_NONCEBYTES long");
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): keypair size should be CRYPTO_BOX_KEYBYTES long");
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (ciphertext_len < crypto_box_MACBYTES) {
        zend_error(E_ERROR,
                   "crypto_box_open(): short ciphertext");
    }
    ciphertext_boxed_len = ciphertext_len + crypto_box_BOXZEROBYTES;
    ciphertext_boxed = safe_emalloc((size_t) ciphertext_boxed_len, 1U, 0U);
    memset(ciphertext_boxed, 0, crypto_box_BOXZEROBYTES);
    memcpy(ciphertext_boxed + crypto_box_BOXZEROBYTES, ciphertext, ciphertext_len);
    out = safe_emalloc((size_t) ciphertext_boxed_len +
                       crypto_box_MACBYTES, 1U, 0U);
    if (crypto_box_open(out, ciphertext_boxed,
                        (unsigned long long) ciphertext_boxed_len,
                        nonce, publickey, secretkey) != 0) {
        RETVAL_FALSE;
    } else {
        RETVAL_STRINGL((char *) out + crypto_box_ZEROBYTES,
                       ciphertext_len - crypto_box_MACBYTES, 1);
    }
    efree(out);
}
