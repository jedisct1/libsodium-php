
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_libsodium.h"

#include <sodium.h>

const zend_function_entry libsodium_functions[] = {
	PHP_FE(sodium_version_string, NULL)
    PHP_FE(sodium_library_version_major, NULL)
    PHP_FE(sodium_library_version_minor, NULL)
	PHP_FE_END	/* Must be the last line in libsodium_functions[] */
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
