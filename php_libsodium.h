
#ifndef PHP_LIBSODIUM_H
#define PHP_LIBSODIUM_H

extern zend_module_entry libsodium_module_entry;
#define phpext_libsodium_ptr &libsodium_module_entry

#define PHP_LIBSODIUM_VERSION "0.1.1"

#ifdef PHP_WIN32
# define PHP_LIBSODIUM_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
# define PHP_LIBSODIUM_API __attribute__ ((visibility("default")))
#else
# define PHP_LIBSODIUM_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(libsodium);
PHP_MSHUTDOWN_FUNCTION(libsodium);
PHP_RINIT_FUNCTION(libsodium);
PHP_RSHUTDOWN_FUNCTION(libsodium);
PHP_MINFO_FUNCTION(libsodium);

PHP_METHOD(Sodium, crypto_aead_chacha20poly1305_decrypt);
PHP_METHOD(Sodium, crypto_aead_chacha20poly1305_encrypt);
PHP_METHOD(Sodium, crypto_box);
PHP_METHOD(Sodium, crypto_box_keypair);
PHP_METHOD(Sodium, crypto_box_keypair_from_secretkey_and_publickey);
PHP_METHOD(Sodium, crypto_box_open);
PHP_METHOD(Sodium, crypto_box_publickey);
PHP_METHOD(Sodium, crypto_box_publickey_from_secretkey);
PHP_METHOD(Sodium, crypto_box_secretkey);
PHP_METHOD(Sodium, crypto_generichash);
PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256);
PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256_str);
PHP_METHOD(Sodium, crypto_pwhash_scryptsalsa208sha256_str_verify);
PHP_METHOD(Sodium, crypto_secretbox);
PHP_METHOD(Sodium, crypto_secretbox_open);
PHP_METHOD(Sodium, crypto_shorthash);
PHP_METHOD(Sodium, crypto_sign);
PHP_METHOD(Sodium, crypto_sign_detached);
PHP_METHOD(Sodium, crypto_sign_keypair);
PHP_METHOD(Sodium, crypto_sign_keypair_from_secretkey_and_publickey);
PHP_METHOD(Sodium, crypto_sign_open);
PHP_METHOD(Sodium, crypto_sign_publickey);
PHP_METHOD(Sodium, crypto_sign_secretkey);
PHP_METHOD(Sodium, crypto_sign_seed_keypair);
PHP_METHOD(Sodium, crypto_sign_verify_detached);
PHP_METHOD(Sodium, crypto_stream);
PHP_METHOD(Sodium, crypto_stream_xor);
PHP_METHOD(Sodium, randombytes_buf);
PHP_METHOD(Sodium, randombytes_random16);
PHP_METHOD(Sodium, randombytes_uniform);
PHP_METHOD(Sodium, sodium_bin2hex);
PHP_METHOD(Sodium, sodium_library_version_major);
PHP_METHOD(Sodium, sodium_library_version_minor);
PHP_METHOD(Sodium, sodium_memcmp);
PHP_METHOD(Sodium, sodium_memzero);
PHP_METHOD(Sodium, sodium_version_string);

#ifdef ZTS
#define LIBSODIUM_G(v) TSRMG(libsodium_globals_id, zend_libsodium_globals *, v)
#else
#define LIBSODIUM_G(v) (libsodium_globals.v)
#endif

#endif  /* PHP_LIBSODIUM_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
