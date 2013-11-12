
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_libsodium.h"

#include <sodium.h>

const int pass_rest_by_reference = 1;
const int pass_arg_by_reference = 0;

ZEND_BEGIN_ARG_INFO(FirstArgByReference, 0)
ZEND_ARG_PASS_INFO(1)
ZEND_END_ARG_INFO()

const zend_function_entry libsodium_functions[] = {
    PHP_FE(sodium_version_string, NULL)
    PHP_FE(sodium_library_version_major, NULL)
    PHP_FE(sodium_library_version_minor, NULL)
    PHP_FE(sodium_memzero, FirstArgByReference)
    PHP_FE(sodium_memcmp, NULL)
    PHP_FE(randombytes_buf, NULL)
    PHP_FE(randombytes_random, NULL)
    PHP_FE(randombytes_uniform, NULL)
    PHP_FE(crypto_shorthash, NULL)
    PHP_FE_END      /* Must be the last line in libsodium_functions[] */
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
        return;
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
    } else {
        RETURN_LONG(sodium_memcmp(buf1, buf2, len1));
    }
}

PHP_FUNCTION(randombytes_buf)
{
    char *buf;
    int   len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &len) == FAILURE ||
        len <= 0) {
        zend_error(E_ERROR, "randombytes_buf(): invalid length");
        return;
    }
    buf = safe_emalloc((size_t) len, 1U, 0U);
    randombytes_buf(buf, (size_t) len);

    RETURN_STRINGL(buf, len, 0);
}

PHP_FUNCTION(randombytes_random)
{
    RETURN_LONG((int) randombytes_random());
}

PHP_FUNCTION(randombytes_uniform)
{
    int upper_bound;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &upper_bound) == FAILURE ||
        upper_bound <= 0) {
        zend_error(E_ERROR, "randombytes_uniform(): invalid upper bound");
        return;
    }
    RETURN_LONG((int) randombytes_uniform((uint32_t) upper_bound));
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
    RETURN_STRINGL((const char *) out, crypto_shorthash_BYTES, 0);
}
