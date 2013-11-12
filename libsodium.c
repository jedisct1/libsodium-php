
#ifdef HAVE_CONFIG_H
#include "config.h"
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
        zend_error(E_ERROR, "sodium_memzero needs a PHP string");
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
        zend_error(E_ERROR, "sodium_memcmp() needs strings of the same length");
    }
    RETURN_LONG(sodium_memcmp(buf1, buf2, len1));
}
