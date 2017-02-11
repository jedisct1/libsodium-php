
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_libsodium.h"
#include "compat.h"
#include "zend_exceptions.h"

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

ZEND_BEGIN_ARG_INFO_EX(AI_String, 0, 0, 1)
  ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_TwoStrings, 0, 0, 2)
  ZEND_ARG_INFO(0, string_1)
  ZEND_ARG_INFO(0, string_2)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_FourStrings, 0, 0, 3)
  ZEND_ARG_INFO(0, string_1)
  ZEND_ARG_INFO(0, string_2)
  ZEND_ARG_INFO(0, string_3)
  ZEND_ARG_INFO(0, string_4)
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

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndKeyPair, 0, 0, 2)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, keypair)
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

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndNonceAndKeyPair, 0, 0, 3)
  ZEND_ARG_INFO(0, string)
  ZEND_ARG_INFO(0, nonce)
  ZEND_ARG_INFO(0, key)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StringAndMaybeKeyAndLength, 0, 0, 1)
  ZEND_ARG_INFO(0, string)
  /* optional */
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

ZEND_BEGIN_ARG_INFO_EX(AI_StateByReference, 0, 0, 1)
  ZEND_ARG_INFO(1, state)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StateByReferenceAndMaybeLength, 0, 0, 1)
  ZEND_ARG_INFO(1, state)
  /* optional */
  ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_StateByReferenceAndString, 0, 0, 2)
  ZEND_ARG_INFO(1, state)
  ZEND_ARG_INFO(0, string)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(AI_MaybeKeyAndLength, 0, 0, 0)
  /* optional */
  ZEND_ARG_INFO(0, key)
  ZEND_ARG_INFO(0, length)
ZEND_END_ARG_INFO()

#ifndef PHP_FE_END
# define PHP_FE_END { NULL, NULL, NULL }
#endif

#if defined(HAVE_CRYPTO_AEAD_AES256GCM) && defined(crypto_aead_aes256gcm_KEYBYTES) && \
    (defined(__amd64) || defined(__amd64__) || defined(__x86_64__) || defined(__i386__) || \
     defined(_M_AMD64) || defined(_M_IX86))
# define HAVE_AESGCM 1
#endif

const zend_function_entry libsodium_functions[] = {
    PHP_FE(sodium_crypto_aead_aes256gcm_is_available, AI_None)
#ifdef HAVE_AESGCM
    PHP_FE(sodium_crypto_aead_aes256gcm_decrypt, AI_StringAndADAndNonceAndKey)
    PHP_FE(sodium_crypto_aead_aes256gcm_encrypt, AI_StringAndADAndNonceAndKey)
#endif
    PHP_FE(sodium_crypto_aead_chacha20poly1305_decrypt, AI_StringAndADAndNonceAndKey)
    PHP_FE(sodium_crypto_aead_chacha20poly1305_encrypt, AI_StringAndADAndNonceAndKey)
#ifdef crypto_aead_chacha20poly1305_IETF_NPUBBYTES
    PHP_FE(sodium_crypto_aead_chacha20poly1305_ietf_decrypt, AI_StringAndADAndNonceAndKey)
    PHP_FE(sodium_crypto_aead_chacha20poly1305_ietf_encrypt, AI_StringAndADAndNonceAndKey)
#endif
    PHP_FE(sodium_crypto_auth, AI_StringAndKey)
    PHP_FE(sodium_crypto_auth_verify, AI_SignatureAndStringAndKey)
    PHP_FE(sodium_crypto_box, AI_StringAndNonceAndKeyPair)
    PHP_FE(sodium_crypto_box_keypair, AI_None)
    PHP_FE(sodium_crypto_box_seed_keypair, AI_Key)
    PHP_FE(sodium_crypto_box_keypair_from_secretkey_and_publickey, AI_SecretKeyAndPublicKey)
    PHP_FE(sodium_crypto_box_open, AI_StringAndNonceAndKey)
    PHP_FE(sodium_crypto_box_publickey, AI_Key)
    PHP_FE(sodium_crypto_box_publickey_from_secretkey, AI_Key)
#ifdef crypto_box_SEALBYTES
    PHP_FE(sodium_crypto_box_seal, AI_StringAndKey)
    PHP_FE(sodium_crypto_box_seal_open, AI_StringAndKey)
#endif
    PHP_FE(sodium_crypto_box_secretkey, AI_Key)
    PHP_FE(sodium_crypto_kx, AI_FourStrings)
    PHP_FE(sodium_crypto_generichash, AI_StringAndMaybeKeyAndLength)
    PHP_FE(sodium_crypto_generichash_init, AI_MaybeKeyAndLength)
    PHP_FE(sodium_crypto_generichash_update, AI_StateByReferenceAndString)
    PHP_FE(sodium_crypto_generichash_final, AI_StateByReferenceAndMaybeLength)
#ifdef crypto_pwhash_SALTBYTES
    PHP_FE(sodium_crypto_pwhash, AI_LengthAndPasswordAndSaltAndOpsLimitAndMemLimit)
    PHP_FE(sodium_crypto_pwhash_str, AI_PasswordAndOpsLimitAndMemLimit)
    PHP_FE(sodium_crypto_pwhash_str_verify, AI_HashAndPassword)
#endif
    PHP_FE(sodium_crypto_pwhash_scryptsalsa208sha256, AI_LengthAndPasswordAndSaltAndOpsLimitAndMemLimit)
    PHP_FE(sodium_crypto_pwhash_scryptsalsa208sha256_str, AI_PasswordAndOpsLimitAndMemLimit)
    PHP_FE(sodium_crypto_pwhash_scryptsalsa208sha256_str_verify, AI_HashAndPassword)
    PHP_FE(sodium_crypto_scalarmult, AI_TwoStrings)
    PHP_FE(sodium_crypto_secretbox, AI_StringAndNonceAndKey)
    PHP_FE(sodium_crypto_secretbox_open, AI_StringAndNonceAndKey)
    PHP_FE(sodium_crypto_shorthash, AI_StringAndKey)
    PHP_FE(sodium_crypto_sign, AI_StringAndKeyPair)
    PHP_FE(sodium_crypto_sign_detached, AI_StringAndKeyPair)
    PHP_FE(sodium_crypto_sign_ed25519_pk_to_curve25519, AI_Key)
    PHP_FE(sodium_crypto_sign_ed25519_sk_to_curve25519, AI_Key)
    PHP_FE(sodium_crypto_sign_keypair, AI_None)
    PHP_FE(sodium_crypto_sign_keypair_from_secretkey_and_publickey, AI_SecretKeyAndPublicKey)
    PHP_FE(sodium_crypto_sign_open, AI_StringAndKeyPair)
    PHP_FE(sodium_crypto_sign_publickey, AI_Key)
    PHP_FE(sodium_crypto_sign_secretkey, AI_Key)
    PHP_FE(sodium_crypto_sign_publickey_from_secretkey, AI_Key)
    PHP_FE(sodium_crypto_sign_seed_keypair, AI_Key)
    PHP_FE(sodium_crypto_sign_verify_detached, AI_SignatureAndStringAndKey)
    PHP_FE(sodium_crypto_stream, AI_LengthAndNonceAndKey)
    PHP_FE(sodium_crypto_stream_xor, AI_StringAndNonceAndKey)
    PHP_FE(sodium_randombytes_buf, AI_Length)
    PHP_FE(sodium_randombytes_random16, AI_None)
    PHP_FE(sodium_randombytes_uniform, AI_Integer)
    PHP_FE(sodium_bin2hex, AI_String)
#if SODIUM_LIBRARY_VERSION_MAJOR > 7 || \
    (SODIUM_LIBRARY_VERSION_MAJOR == 7 && SODIUM_LIBRARY_VERSION_MINOR >= 6)
    PHP_FE(sodium_compare, AI_TwoStrings)
#endif
    PHP_FE(sodium_hex2bin, AI_TwoStrings)
    PHP_FE(sodium_increment, AI_String)
    PHP_FE(sodium_add, AI_TwoStrings)
    PHP_FE(sodium_library_version_major, AI_None)
    PHP_FE(sodium_library_version_minor, AI_None)
    PHP_FE(sodium_memcmp, AI_TwoStrings)
    PHP_FE(sodium_memzero, AI_FirstArgByReferenceSecondLength)
    PHP_FE(sodium_version_string, AI_None)

    PHP_FALIAS(sodium_crypto_scalarmult_base, sodium_crypto_box_publickey_from_secretkey, AI_TwoStrings)

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

#ifdef HAVE_AESGCM
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES",
                           crypto_aead_aes256gcm_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_AES256GCM_NSECBYTES",
                           crypto_aead_aes256gcm_NSECBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES",
                           crypto_aead_aes256gcm_NPUBBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_AES256GCM_ABYTES",
                           crypto_aead_aes256gcm_ABYTES, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES",
                           crypto_aead_chacha20poly1305_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES",
                           crypto_aead_chacha20poly1305_NSECBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES",
                           crypto_aead_chacha20poly1305_NPUBBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES",
                           crypto_aead_chacha20poly1305_ABYTES, CONST_CS | CONST_PERSISTENT);
#ifdef crypto_aead_chacha20poly1305_IETF_NPUBBYTES
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES",
                           crypto_aead_chacha20poly1305_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES",
                           crypto_aead_chacha20poly1305_NSECBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES",
                           crypto_aead_chacha20poly1305_IETF_NPUBBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES",
                           crypto_aead_chacha20poly1305_ABYTES, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AUTH_BYTES",
                           crypto_auth_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_AUTH_KEYBYTES",
                           crypto_auth_KEYBYTES, CONST_CS | CONST_PERSISTENT);
#ifdef crypto_box_SEALBYTES
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_SEALBYTES",
                           crypto_box_SEALBYTES, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_SECRETKEYBYTES",
                           crypto_box_SECRETKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_PUBLICKEYBYTES",
                           crypto_box_PUBLICKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_KEYPAIRBYTES",
                           crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES,
                           CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_MACBYTES",
                           crypto_box_MACBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_NONCEBYTES",
                           crypto_box_NONCEBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_BOX_SEEDBYTES",
                           crypto_box_SEEDBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_KX_BYTES",
                           crypto_kx_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_KX_PUBLICKEYBYTES",
                           crypto_kx_PUBLICKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_KX_SECRETKEYBYTES",
                           crypto_kx_SECRETKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_BYTES",
                           crypto_generichash_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_BYTES_MIN",
                           crypto_generichash_BYTES_MIN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_BYTES_MAX",
                           crypto_generichash_BYTES_MAX, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_KEYBYTES",
                           crypto_generichash_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN",
                           crypto_generichash_KEYBYTES_MIN, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX",
                           crypto_generichash_KEYBYTES_MAX, CONST_CS | CONST_PERSISTENT);
#ifdef crypto_pwhash_SALTBYTES
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SALTBYTES",
                           crypto_pwhash_SALTBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("SODIUM_CRYPTO_PWHASH_STRPREFIX",
                             crypto_pwhash_STRPREFIX, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE",
                           crypto_pwhash_opslimit_interactive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE",
                           crypto_pwhash_memlimit_interactive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE",
                           crypto_pwhash_opslimit_moderate(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE",
                           crypto_pwhash_memlimit_moderate(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE",
                           crypto_pwhash_opslimit_sensitive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE",
                           crypto_pwhash_memlimit_sensitive(), CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES",
                           crypto_pwhash_scryptsalsa208sha256_SALTBYTES, CONST_CS | CONST_PERSISTENT);
#ifndef crypto_pwhash_scryptsalsa208sha256_STRPREFIX
# define crypto_pwhash_scryptsalsa208sha256_STRPREFIX "$7$"
#endif
    REGISTER_STRING_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX",
                             crypto_pwhash_scryptsalsa208sha256_STRPREFIX, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE",
                           crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE",
                           crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE",
                           crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE",
                           crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(), CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SCALARMULT_BYTES",
                           crypto_scalarmult_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SCALARMULT_SCALARBYTES",
                           crypto_scalarmult_SCALARBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SHORTHASH_BYTES",
                           crypto_shorthash_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SHORTHASH_KEYBYTES",
                           crypto_shorthash_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SECRETBOX_KEYBYTES",
                           crypto_secretbox_KEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SECRETBOX_MACBYTES",
                           crypto_secretbox_MACBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SECRETBOX_NONCEBYTES",
                           crypto_secretbox_NONCEBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SIGN_BYTES",
                           crypto_sign_BYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SIGN_SEEDBYTES",
                           crypto_sign_SEEDBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES",
                           crypto_sign_PUBLICKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SIGN_SECRETKEYBYTES",
                           crypto_sign_SECRETKEYBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_SIGN_KEYPAIRBYTES",
                           crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES,
                           CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_STREAM_NONCEBYTES",
                           crypto_stream_NONCEBYTES, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SODIUM_CRYPTO_STREAM_KEYBYTES",
                           crypto_stream_KEYBYTES, CONST_CS | CONST_PERSISTENT);
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
    php_info_print_table_header(2, "libsodium compiled version", PHP_LIBSODIUM_VERSION);
    php_info_print_table_header(2, "libsodium headers version", SODIUM_VERSION_STRING);
    php_info_print_table_header(2, "libsodium library version", sodium_version_string());
    php_info_print_table_end();
}

PHP_FUNCTION(sodium_version_string)
{
    RETURN_STRING(sodium_version_string());
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
    zval      *buf_zv;
    char      *buf;
    strsize_t  buf_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                              "z", &buf_zv) == FAILURE) {
        return;
    }
    ZVAL_DEREF(buf_zv);
    if (Z_TYPE_P(buf_zv) != IS_STRING) {
        zend_throw_exception(zend_ce_exception, "memzero: a PHP string is required", 0);
        return;
    }
    if (HAS_MORE_REFS(buf_zv)) {
        convert_to_null(buf_zv);
        return;
    }
    buf = Z_STRVAL(*buf_zv);
    buf_len = Z_STRLEN(*buf_zv);
    if (buf_len > 0) {
        sodium_memzero(buf, (size_t) buf_len);
    }
    convert_to_null(buf_zv);
}

PHP_FUNCTION(sodium_increment)
{
    zval          *val_zv;
    unsigned char *val;
    strsize_t      i;
    strsize_t      val_len;
    unsigned int   c;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                              "z", &val_zv) == FAILURE) {
        return;
    }
    ZVAL_DEREF(val_zv);
    if (IS_IMMUTABLE(val_zv)) {
        zend_throw_exception(zend_ce_exception, "increment(): value is immutable", 0);
        return;
    }
    if (Z_TYPE_P(val_zv) != IS_STRING) {
        zend_throw_exception(zend_ce_exception, "increment(): a PHP string is required", 0);
        return;
    }
    val = (unsigned char *) Z_STRVAL(*val_zv);
    val_len = Z_STRLEN(*val_zv);
    c = 1U << 8;
    for (i = (strsize_t) 0U; i < val_len; i++) {
        c >>= 8;
        c += val[i];
        val[i] = (unsigned char) c;
    }
}

PHP_FUNCTION(sodium_add)
{
    zval          *val_zv;
    unsigned char *val;
    unsigned char *addv;
    strsize_t      i;
    strsize_t      val_len;
    strsize_t      addv_len;
    unsigned int   c;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,
                              "zs", &val_zv, &addv, &addv_len) == FAILURE) {
        return;
    }
    ZVAL_DEREF(val_zv);
    if (IS_IMMUTABLE(val_zv)) {
        zend_throw_exception(zend_ce_exception, "add(): value is immutable", 0);
        return;
    }
    if (Z_TYPE_P(val_zv) != IS_STRING) {
        zend_throw_exception(zend_ce_exception, "add(): PHP strings are required", 0);
        return;
    }
    val = (unsigned char *) Z_STRVAL(*val_zv);
    val_len = Z_STRLEN(*val_zv);
    if (val_len != addv_len) {
        zend_throw_exception(zend_ce_exception, "add(): values must have the same length", 0);
        return;
    }
    c = 0U;
    for (i = (strsize_t) 0U; i < val_len; i++) {
        c += val[i] + addv[i];
        val[i] = (unsigned char) c;
        c >>= 8;
    }
}

PHP_FUNCTION(sodium_memcmp)
{
    char      *buf1;
    char      *buf2;
    strsize_t  len1;
    strsize_t  len2;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &buf1, &len1,
                              &buf2, &len2) == FAILURE) {
        return;
    }
    if (len1 != len2) {
        RETURN_LONG(-1);
    } else if (len1 > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "memcmp(): invalid length", 0);
        return;
    } else {
        RETURN_LONG(sodium_memcmp(buf1, buf2, (size_t) len1));
    }
}

PHP_FUNCTION(sodium_randombytes_buf)
{
    zend_string *buf;
    zend_long    len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &len) == FAILURE ||
        len < 0 || len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "randombytes_buf(): invalid length", 0);
        return;
    }
    buf = zend_string_alloc((size_t) len, 0);
    randombytes_buf(ZSTR_VAL(buf), (size_t) ZSTR_LEN(buf));
    ZSTR_VAL(buf)[len] = 0;

    RETURN_STR(buf);
}

PHP_FUNCTION(sodium_randombytes_random16)
{
    RETURN_LONG((zend_long) (randombytes_random() & (uint32_t) 0xffff));
}

PHP_FUNCTION(sodium_randombytes_uniform)
{
    zend_long upper_bound;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",
                              &upper_bound) == FAILURE ||
        upper_bound <= 0 || upper_bound > INT32_MAX) {
        zend_throw_exception(zend_ce_exception, "randombytes_uniform(): invalid upper bound", 0);
        return;
    }

    RETURN_LONG((zend_long) randombytes_uniform((uint32_t) upper_bound));
}

PHP_FUNCTION(sodium_crypto_shorthash)
{
    zend_string   *hash;
    unsigned char *key;
    unsigned char *msg;
    strsize_t      key_len;
    strsize_t      msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (key_len != crypto_shorthash_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_shorthash(): key size should be "
                   "CRYPTO_SHORTHASH_KEYBYTES bytes",
                   0);
        return;
    }
    hash = zend_string_alloc(crypto_shorthash_BYTES, 0);
    if (crypto_shorthash((unsigned char *) ZSTR_VAL(hash), msg,
                         (unsigned long long) msg_len, key) != 0) {
        zend_string_free(hash);
        zend_throw_exception(zend_ce_error, "crypto_shorthash(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash)[crypto_shorthash_BYTES] = 0;

    RETURN_STR(hash);
}

PHP_FUNCTION(sodium_crypto_secretbox)
{
    zend_string   *ciphertext;
    unsigned char *key;
    unsigned char *msg;
    unsigned char *nonce;
    strsize_t      key_len;
    strsize_t      msg_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_secretbox(): nonce size should be "
                   "CRYPTO_SECRETBOX_NONCEBYTES bytes",
                   0);
        return;
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_secretbox(): key size should be "
                   "CRYPTO_SECRETBOX_KEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_secretbox_MACBYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext = zend_string_alloc((size_t) msg_len + crypto_secretbox_MACBYTES, 0);
    if (crypto_secretbox_easy((unsigned char *) ZSTR_VAL(ciphertext),
                              msg, (unsigned long long) msg_len,
                              nonce, key) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_secretbox(): internal error", 0);
    }
    ZSTR_VAL(ciphertext)[msg_len + crypto_secretbox_MACBYTES] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_secretbox_open)
{
    zend_string   *msg;
    unsigned char *key;
    unsigned char *ciphertext;
    unsigned char *nonce;
    strsize_t      key_len;
    strsize_t      ciphertext_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_secretbox_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_secretbox_open(): nonce size should be "
                   "CRYPTO_SECRETBOX_NONCEBYTES bytes",
                   0);
        return;
    }
    if (key_len != crypto_secretbox_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_secretbox_open(): key size should be "
                   "CRYPTO_SECRETBOX_KEYBYTES bytes",
                   0);
        return;
    }
    if (ciphertext_len < crypto_secretbox_MACBYTES) {
        RETURN_FALSE;
    }
    msg = zend_string_alloc
        ((size_t) ciphertext_len - crypto_secretbox_MACBYTES, 0);
    if (crypto_secretbox_open_easy((unsigned char *) ZSTR_VAL(msg), ciphertext,
                                   (unsigned long long) ciphertext_len,
                                   nonce, key) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    } else {
        ZSTR_VAL(msg)[ciphertext_len - crypto_secretbox_MACBYTES] = 0;
        RETURN_STR(msg);
    }
}

PHP_FUNCTION(sodium_crypto_generichash)
{
    zend_string   *hash;
    unsigned char *key = NULL;
    unsigned char *msg;
    zend_long      hash_len = crypto_generichash_BYTES;
    strsize_t      key_len = 0;
    strsize_t      msg_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|sl",
                              &msg, &msg_len,
                              &key, &key_len,
                              &hash_len) == FAILURE) {
        return;
    }
    if (hash_len < crypto_generichash_BYTES_MIN ||
        hash_len > crypto_generichash_BYTES_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash(): unsupported output length", 0);
        return;
    }
    if (key_len != 0 &&
        (key_len < crypto_generichash_KEYBYTES_MIN ||
         key_len > crypto_generichash_KEYBYTES_MAX)) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash(): unsupported key length", 0);
        return;
    }
    hash = zend_string_alloc(hash_len, 0);
    if (crypto_generichash((unsigned char *) ZSTR_VAL(hash), (size_t) hash_len,
                           msg, (unsigned long long) msg_len,
                           key, (size_t) key_len) != 0) {
        zend_string_free(hash);
        zend_throw_exception(zend_ce_error, "crypto_generichash(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash)[hash_len] = 0;

    RETURN_STR(hash);
}

PHP_FUNCTION(sodium_crypto_generichash_init)
{
    crypto_generichash_state  state_tmp;
    zend_string              *state;
    unsigned char            *key = NULL;
    size_t                    state_len = sizeof (crypto_generichash_state);
    zend_long                 hash_len = crypto_generichash_BYTES;
    strsize_t                 key_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|sl",
                              &key, &key_len,
                              &hash_len) == FAILURE) {
        return;
    }
    if (hash_len < crypto_generichash_BYTES_MIN ||
        hash_len > crypto_generichash_BYTES_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_init(): unsupported output length", 0);
        return;
    }
    if (key_len != 0 &&
        (key_len < crypto_generichash_KEYBYTES_MIN ||
         key_len > crypto_generichash_KEYBYTES_MAX)) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_init(): unsupported key length", 0);
    }
    if (crypto_generichash_init((void *) &state_tmp, key, (size_t) key_len,
                                (size_t) hash_len) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_generichash_init(): internal error", 0);
        return;
    }
    state = zend_string_alloc(state_len, 0);
    memcpy(ZSTR_VAL(state), &state_tmp, state_len);
    sodium_memzero(&state_tmp, sizeof state_tmp);
    ZSTR_VAL(state)[state_len] = 0;

    RETURN_STR(state);
}

PHP_FUNCTION(sodium_crypto_generichash_update)
{
    crypto_generichash_state  state_tmp;
    zval                     *state_zv;
    unsigned char            *msg;
    unsigned char            *state;
    strsize_t                 msg_len;
    strsize_t                 state_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs",
                              &state_zv, &msg, &msg_len) == FAILURE) {
        return;
    }
    ZVAL_DEREF(state_zv);
    if (Z_TYPE_P(state_zv) != IS_STRING) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_update: a reference to a state is required", 0);
        return;
    }
    state = (unsigned char *) Z_STRVAL(*state_zv);
    state_len = Z_STRLEN(*state_zv);
    if (state_len != sizeof (crypto_generichash_state)) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_update(): incorrect state length", 0);
        return;
    }
    memcpy(&state_tmp, state, sizeof state_tmp);
    if (crypto_generichash_update((void *) &state_tmp, msg,
                                  (unsigned long long) msg_len) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_generichash_update(): internal error", 0);
        return;
    }
    memcpy(state, &state_tmp, state_len);
    sodium_memzero(&state_tmp, sizeof state_tmp);

    RETURN_TRUE;
}

PHP_FUNCTION(sodium_crypto_generichash_final)
{
    crypto_generichash_state  state_tmp;
    zend_string              *hash;
    zval                     *state_zv;
    unsigned char            *state;
    strsize_t                 state_len;
    zend_long                 hash_len = crypto_generichash_BYTES;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l",
                              &state_zv, &hash_len) == FAILURE) {
        return;
    }
    ZVAL_DEREF(state_zv);
    if (Z_TYPE_P(state_zv) != IS_STRING) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_final: a reference to a state is required", 0);
        return;
    }
    state = (unsigned char *) Z_STRVAL(*state_zv);
    state_len = Z_STRLEN(*state_zv);
    if (state_len != sizeof (crypto_generichash_state)) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_final(): incorrect state length", 0);
        return;
    }
    if (hash_len < crypto_generichash_BYTES_MIN ||
        hash_len > crypto_generichash_BYTES_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_generichash_final(): unsupported output length", 0);
        return;
    }
    hash = zend_string_alloc(hash_len, 0);
    memcpy(&state_tmp, state, sizeof state_tmp);
    if (crypto_generichash_final((void *) &state_tmp,
                                 (unsigned char *) ZSTR_VAL(hash),
                                 (size_t) hash_len) != 0) {
        zend_string_free(hash);
        zend_throw_exception(zend_ce_error, "crypto_generichash_final(): internal error", 0);
        return;
    }
    sodium_memzero(state, state_len);
    convert_to_null(state_zv);
    ZSTR_VAL(hash)[hash_len] = 0;

    RETURN_STR(hash);
}

PHP_FUNCTION(sodium_crypto_box_keypair)
{
    zend_string *keypair;
    size_t       keypair_len;

    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    if (crypto_box_keypair((unsigned char *) ZSTR_VAL(keypair) +
                           crypto_box_SECRETKEYBYTES,
                           (unsigned char *) ZSTR_VAL(keypair)) != 0) {
        zend_string_free(keypair);
        zend_throw_exception(zend_ce_error, "crypto_box_keypair(): internal error", 0);
        return;
    }
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_box_seed_keypair)
{
    zend_string   *keypair;
    unsigned char *seed;
    size_t         keypair_len;
    strsize_t      seed_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &seed, &seed_len) == FAILURE) {
        return;
    }
    if (seed_len != crypto_box_SEEDBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_seed_keypair(): "
                   "seed should be crypto_box_SEEDBYTES long",
                   0);
        return;
    }
    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    if (crypto_box_seed_keypair((unsigned char *) ZSTR_VAL(keypair) +
                                 crypto_box_SECRETKEYBYTES,
                                 (unsigned char *) ZSTR_VAL(keypair),
                                 seed) != 0) {
        zend_string_free(keypair);
        zend_throw_exception(zend_ce_error, "crypto_box_seed_keypair(): internal error", 0);
        return;
    }
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_box_keypair_from_secretkey_and_publickey)
{
    zend_string *keypair;
    char        *publickey;
    char        *secretkey;
    size_t       keypair_len;
    strsize_t    publickey_len;
    strsize_t    secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &secretkey, &secretkey_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_box_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_keypair_from_secretkey_and_publickey(): "
                   "secretkey should be CRYPTO_BOX_SECRETKEYBYTES long",
                   0);
        return;
    }
    if (publickey_len != crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_keypair_from_secretkey_and_publickey(): "
                   "publickey should be CRYPTO_BOX_PUBLICKEYBYTES long",
                   0);
        return;
    }
    keypair_len = crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    memcpy(ZSTR_VAL(keypair), secretkey, crypto_box_SECRETKEYBYTES);
    memcpy(ZSTR_VAL(keypair) + crypto_box_SECRETKEYBYTES, publickey,
           crypto_box_PUBLICKEYBYTES);
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_box_secretkey)
{
    zend_string   *secretkey;
    unsigned char *keypair;
    strsize_t      keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_secretkey(): keypair should be "
                   "CRYPTO_BOX_KEYPAIRBYTES long",
                   0);
        return;
    }
    secretkey = zend_string_alloc(crypto_box_SECRETKEYBYTES, 0);
    memcpy(ZSTR_VAL(secretkey), keypair, crypto_box_SECRETKEYBYTES);
    ZSTR_VAL(secretkey)[crypto_box_SECRETKEYBYTES] = 0;

    RETURN_STR(secretkey);
}

PHP_FUNCTION(sodium_crypto_box_publickey)
{
    zend_string   *publickey;
    unsigned char *keypair;
    strsize_t      keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_publickey(): keypair should be "
                   "CRYPTO_BOX_KEYPAIRBYTES long",
                   0);
        return;
    }
    publickey = zend_string_alloc(crypto_box_PUBLICKEYBYTES, 0);
    memcpy(ZSTR_VAL(publickey), keypair + crypto_box_SECRETKEYBYTES,
           crypto_box_PUBLICKEYBYTES);
    ZSTR_VAL(publickey)[crypto_box_PUBLICKEYBYTES] = 0;

    RETURN_STR(publickey);
}

PHP_FUNCTION(sodium_crypto_box_publickey_from_secretkey)
{
    zend_string   *publickey;
    unsigned char *secretkey;
    strsize_t      secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_box_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_publickey_from_secretkey(): key should be "
                   "CRYPTO_BOX_SECRETKEYBYTES long",
                   0);
        return;
    }
    publickey = zend_string_alloc(crypto_box_PUBLICKEYBYTES, 0);
    (void) sizeof(int[crypto_scalarmult_BYTES ==
                      crypto_box_PUBLICKEYBYTES ? 1 : -1]);
    (void) sizeof(int[crypto_scalarmult_SCALARBYTES ==
                      crypto_box_SECRETKEYBYTES ? 1 : -1]);
    crypto_scalarmult_base((unsigned char *) ZSTR_VAL(publickey), secretkey);
    ZSTR_VAL(publickey)[crypto_box_PUBLICKEYBYTES] = 0;

    RETURN_STR(publickey);
}

PHP_FUNCTION(sodium_crypto_box)
{
    zend_string   *ciphertext;
    unsigned char *keypair;
    unsigned char *msg;
    unsigned char *nonce;
    unsigned char *publickey;
    unsigned char *secretkey;
    strsize_t      keypair_len;
    strsize_t      msg_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box(): nonce size should be "
                   "CRYPTO_BOX_NONCEBYTES bytes",
                   0);
        return;
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box(): keypair size should be "
                   "CRYPTO_BOX_KEYPAIRBYTES bytes",
                   0);
        return;
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (STRSIZE_MAX - msg_len <= crypto_box_MACBYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext = zend_string_alloc((size_t) msg_len + crypto_box_MACBYTES, 0);
    if (crypto_box_easy((unsigned char *) ZSTR_VAL(ciphertext), msg,
                        (unsigned long long) msg_len,
                        nonce, publickey, secretkey) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_box(): internal error", 0);
        return;
    }
    ZSTR_VAL(ciphertext)[msg_len + crypto_box_MACBYTES] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_box_open)
{
    zend_string   *msg;
    unsigned char *ciphertext;
    unsigned char *keypair;
    unsigned char *nonce;
    unsigned char *publickey;
    unsigned char *secretkey;
    strsize_t      ciphertext_len;
    strsize_t      keypair_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &ciphertext, &ciphertext_len,
                              &nonce, &nonce_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_box_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_open(): nonce size should be "
                   "CRYPTO_BOX_NONCEBYTES bytes",
                   0);
        return;
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_open(): keypair size should be "
                   "CRYPTO_BOX_KEYBYTES bytes",
                   0);
        return;
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (ciphertext_len < crypto_box_MACBYTES) {
        RETURN_FALSE;
    }
    msg = zend_string_alloc((size_t) ciphertext_len - crypto_box_MACBYTES, 0);
    if (crypto_box_open_easy((unsigned char *) ZSTR_VAL(msg), ciphertext,
                             (unsigned long long) ciphertext_len,
                             nonce, publickey, secretkey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    } else {
        ZSTR_VAL(msg)[ciphertext_len - crypto_box_MACBYTES] = 0;
        RETURN_STR(msg);
    }
}

#ifdef crypto_box_SEALBYTES
PHP_FUNCTION(sodium_crypto_box_seal)
{
    zend_string   *ciphertext;
    unsigned char *msg;
    unsigned char *publickey;
    strsize_t      msg_len;
    strsize_t      publickey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (publickey_len != crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_seal(): public key size should be "
                   "CRYPTO_BOX_PUBLICKEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_box_SEALBYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext = zend_string_alloc((size_t) msg_len + crypto_box_SEALBYTES, 0);
    if (crypto_box_seal((unsigned char *) ZSTR_VAL(ciphertext), msg,
                        (unsigned long long) msg_len, publickey) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_box_seal(): internal error", 0);
        return;
    }
    ZSTR_VAL(ciphertext)[msg_len + crypto_box_SEALBYTES] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_box_seal_open)
{
    zend_string   *msg;
    unsigned char *ciphertext;
    unsigned char *keypair;
    unsigned char *publickey;
    unsigned char *secretkey;
    strsize_t      ciphertext_len;
    strsize_t      keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &ciphertext, &ciphertext_len,
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len != crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_box_seal_open(): keypair size should be "
                   "CRYPTO_BOX_KEYBYTES bytes",
                   0);
        return;
    }
    secretkey = keypair;
    publickey = keypair + crypto_box_SECRETKEYBYTES;
    if (ciphertext_len < crypto_box_SEALBYTES) {
        RETURN_FALSE;
    }
    msg = zend_string_alloc((size_t) ciphertext_len - crypto_box_SEALBYTES, 0);
    if (crypto_box_seal_open((unsigned char *) ZSTR_VAL(msg), ciphertext,
                             (unsigned long long) ciphertext_len,
                             publickey, secretkey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    } else {
        ZSTR_VAL(msg)[ciphertext_len - crypto_box_SEALBYTES] = 0;
        RETURN_STR(msg);
    }
}
#endif

PHP_FUNCTION(sodium_crypto_sign_keypair)
{
    zend_string *keypair;
    size_t       keypair_len;

    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    if (crypto_sign_keypair((unsigned char *) ZSTR_VAL(keypair) +
                            crypto_sign_SECRETKEYBYTES,
                            (unsigned char *) ZSTR_VAL(keypair)) != 0) {
        zend_string_free(keypair);
        zend_throw_exception(zend_ce_error, "crypto_sign_keypair(): internal error", 0);
        return;
    }
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_sign_seed_keypair)
{
    zend_string   *keypair;
    unsigned char *seed;
    size_t         keypair_len;
    strsize_t      seed_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &seed, &seed_len) == FAILURE) {
        return;
    }
    if (seed_len != crypto_sign_SEEDBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_seed_keypair(): "
                   "seed should be crypto_sign_SEEDBYTES long",
                   0);
        return;
    }
    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    if (crypto_sign_seed_keypair((unsigned char *) ZSTR_VAL(keypair) +
                                 crypto_sign_SECRETKEYBYTES,
                                 (unsigned char *) ZSTR_VAL(keypair),
                                 seed) != 0) {
        zend_string_free(keypair);
        zend_throw_exception(zend_ce_error, "crypto_sign_seed_keypair(): internal error", 0);
    }
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_sign_keypair_from_secretkey_and_publickey)
{
    zend_string *keypair;
    char        *publickey;
    char        *secretkey;
    size_t       keypair_len;
    strsize_t    publickey_len;
    strsize_t    secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &secretkey, &secretkey_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_keypair_from_secretkey_and_publickey(): "
                   "secretkey should be CRYPTO_SIGN_SECRETKEYBYTES long",
                   0);
        return;
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_keypair_from_secretkey_and_publickey(): "
                   "publickey should be CRYPTO_SIGN_PUBLICKEYBYTES long",
                   0);
        return;
    }
    keypair_len = crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES;
    keypair = zend_string_alloc(keypair_len, 0);
    memcpy(ZSTR_VAL(keypair), secretkey, crypto_sign_SECRETKEYBYTES);
    memcpy(ZSTR_VAL(keypair) + crypto_sign_SECRETKEYBYTES, publickey,
           crypto_sign_PUBLICKEYBYTES);
    ZSTR_VAL(keypair)[keypair_len] = 0;

    RETURN_STR(keypair);
}

PHP_FUNCTION(sodium_crypto_sign_publickey_from_secretkey)
{
    zend_string *publickey;
    char        *secretkey;
    strsize_t    secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_publickey_from_secretkey(): "
                   "secretkey should be CRYPTO_SIGN_SECRETKEYBYTES long",
                   0);
        return;
    }
    publickey = zend_string_alloc(crypto_sign_PUBLICKEYBYTES, 0);

    if (crypto_sign_ed25519_sk_to_pk((unsigned char *) ZSTR_VAL(publickey),
                                     (const unsigned char *) secretkey) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_sign(): internal error", 0);
        return;
    }
    ZSTR_VAL(publickey)[crypto_sign_PUBLICKEYBYTES] = 0;

    RETURN_STR(publickey);
}

PHP_FUNCTION(sodium_crypto_sign_secretkey)
{
    zend_string   *secretkey;
    unsigned char *keypair;
    strsize_t      keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_secretkey(): keypair should be "
                   "CRYPTO_SIGN_KEYPAIRBYTES long",
                   0);
        return;
    }
    secretkey = zend_string_alloc(crypto_sign_SECRETKEYBYTES, 0);
    memcpy(ZSTR_VAL(secretkey), keypair, crypto_sign_SECRETKEYBYTES);
    ZSTR_VAL(secretkey)[crypto_sign_SECRETKEYBYTES] = 0;

    RETURN_STR(secretkey);
}

PHP_FUNCTION(sodium_crypto_sign_publickey)
{
    zend_string   *publickey;
    unsigned char *keypair;
    strsize_t      keypair_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &keypair, &keypair_len) == FAILURE) {
        return;
    }
    if (keypair_len !=
        crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_publickey(): keypair should be "
                   "CRYPTO_SIGN_KEYPAIRBYTES long",
                   0);
        return;
    }
    publickey = zend_string_alloc(crypto_sign_PUBLICKEYBYTES, 0);
    memcpy(ZSTR_VAL(publickey), keypair + crypto_sign_SECRETKEYBYTES,
           crypto_sign_PUBLICKEYBYTES);
    ZSTR_VAL(publickey)[crypto_sign_PUBLICKEYBYTES] = 0;

    RETURN_STR(publickey);
}

PHP_FUNCTION(sodium_crypto_sign)
{
    zend_string        *msg_signed;
    unsigned char      *msg;
    unsigned char      *secretkey;
    unsigned long long  msg_signed_real_len;
    strsize_t           msg_len;
    strsize_t           msg_signed_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign(): secret key size should be "
                   "CRYPTO_SIGN_SECRETKEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_sign_BYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    msg_signed_len = msg_len + crypto_sign_BYTES;
    msg_signed = zend_string_alloc((size_t) msg_signed_len, 0);
    if (crypto_sign((unsigned char *) ZSTR_VAL(msg_signed),
                    &msg_signed_real_len, msg,
                    (unsigned long long) msg_len, secretkey) != 0) {
        zend_string_free(msg_signed);
        zend_throw_exception(zend_ce_error, "crypto_sign(): internal error", 0);
        return;
    }
    if (msg_signed_real_len <= 0U || msg_signed_real_len >= STRSIZE_MAX ||
        msg_signed_real_len > msg_signed_len) {
        zend_string_free(msg_signed);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(msg_signed, (strsize_t) msg_signed_real_len);
    ZSTR_VAL(msg_signed)[msg_signed_real_len] = 0;

    RETURN_STR(msg_signed);
}

PHP_FUNCTION(sodium_crypto_sign_open)
{
    zend_string        *msg;
    unsigned char      *msg_signed;
    unsigned char      *publickey;
    unsigned long long  msg_real_len;
    strsize_t           msg_len;
    strsize_t           msg_signed_len;
    strsize_t           publickey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg_signed, &msg_signed_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_open(): public key size should be "
                   "CRYPTO_SIGN_PUBLICKEYBYTES bytes",
                   0);
        return;
    }
    msg_len = msg_signed_len;
    if (msg_len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    msg = zend_string_alloc((size_t) msg_len, 0);
    if (crypto_sign_open((unsigned char *) ZSTR_VAL(msg), &msg_real_len,
                         msg_signed, (unsigned long long) msg_signed_len,
                         publickey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    }
    if (msg_real_len >= STRSIZE_MAX || msg_real_len > msg_signed_len) {
        zend_string_free(msg);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(msg, (strsize_t) msg_real_len);
    ZSTR_VAL(msg)[msg_real_len] = 0;

    RETURN_STR(msg);
}

PHP_FUNCTION(sodium_crypto_sign_detached)
{
    zend_string        *signature;
    unsigned char      *msg;
    unsigned char      *secretkey;
    unsigned long long  signature_real_len;
    strsize_t           msg_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_sign_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_detached(): secret key size should be "
                   "CRYPTO_SIGN_SECRETKEYBYTES bytes",
                   0);
        return;
    }
    signature = zend_string_alloc((size_t) crypto_sign_BYTES, 0);
    if (crypto_sign_detached((unsigned char *) ZSTR_VAL(signature),
                             &signature_real_len, msg,
                             (unsigned long long) msg_len, secretkey) != 0) {
        zend_string_free(signature);
        zend_throw_exception(zend_ce_exception, "crypto_sign_detached()", 0);
        return;
    }
    if (signature_real_len <= 0U || signature_real_len > crypto_sign_BYTES) {
        zend_string_free(signature);
        zend_throw_exception(zend_ce_exception, "signature has a bogus size", 0);
        return;
    }
    ZSTR_TRUNCATE(signature, (strsize_t) signature_real_len);
    ZSTR_VAL(signature)[signature_real_len] = 0;

    RETURN_STR(signature);
}

PHP_FUNCTION(sodium_crypto_sign_verify_detached)
{
    unsigned char *msg;
    unsigned char *publickey;
    unsigned char *signature;
    strsize_t      msg_len;
    strsize_t      publickey_len;
    strsize_t      signature_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &signature, &signature_len,
                              &msg, &msg_len,
                              &publickey, &publickey_len) == FAILURE) {
        return;
    }
    if (signature_len != crypto_sign_BYTES) {
        zend_throw_exception(zend_ce_exception, 
                   "crypto_sign_verify_detached(): signature size should be "
                   "CRYPTO_SIGN_BYTES bytes",
                   0);
        return;
    }
    if (publickey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_verify_detached(): public key size should be "
                   "CRYPTO_SIGN_PUBLICKEYBYTES bytes",
                   0);
        return;
    }
    if (crypto_sign_verify_detached(signature,
                                    msg, (unsigned long long) msg_len,
                                    publickey) != 0) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_FUNCTION(sodium_crypto_stream)
{
    zend_string   *ciphertext;
    unsigned char *key;
    unsigned char *nonce;
    zend_long      ciphertext_len;
    strsize_t      key_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lss",
                              &ciphertext_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (ciphertext_len <= 0 || ciphertext_len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_stream(): invalid length", 0);
        return;
    }
    if (nonce_len != crypto_stream_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception, "nonce should be CRYPTO_STREAM_NONCEBYTES bytes", 0);
        return;
    }
    if (key_len != crypto_stream_KEYBYTES) {
        zend_throw_exception(zend_ce_exception, "key should be CRYPTO_STREAM_KEYBYTES bytes", 0);
        return;
    }
    ciphertext = zend_string_alloc((size_t) ciphertext_len, 0);
    if (crypto_stream((unsigned char *) ZSTR_VAL(ciphertext),
                      (unsigned long long) ciphertext_len, nonce, key) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_stream(): internal error", 0);
        return;
    }
    ZSTR_VAL(ciphertext)[ciphertext_len] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_stream_xor)
{
    zend_string   *ciphertext;
    unsigned char *key;
    unsigned char *msg;
    unsigned char *nonce;
    strsize_t      ciphertext_len;
    strsize_t      key_len;
    strsize_t      msg_len;
    strsize_t      nonce_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &msg, &msg_len,
                              &nonce, &nonce_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (nonce_len != crypto_stream_NONCEBYTES) {
        zend_throw_exception(zend_ce_exception, "nonce should be CRYPTO_STREAM_NONCEBYTES bytes", 0);
    }
    if (key_len != crypto_stream_KEYBYTES) {
        zend_throw_exception(zend_ce_exception, "key should be CRYPTO_STREAM_KEYBYTES bytes", 0);
    }
    ciphertext_len = msg_len;
    ciphertext = zend_string_alloc((size_t) ciphertext_len, 0);
    if (crypto_stream_xor((unsigned char *) ZSTR_VAL(ciphertext), msg,
                          (unsigned long long) msg_len, nonce, key) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_stream_xor(): internal error", 0);
    }
    ZSTR_VAL(ciphertext)[ciphertext_len] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_pwhash_scryptsalsa208sha256)
{
    zend_string   *hash;
    unsigned char *salt;
    char          *passwd;
    zend_long      hash_len;
    zend_long      memlimit;
    zend_long      opslimit;
    strsize_t      passwd_len;
    strsize_t      salt_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lssll",
                              &hash_len,
                              &passwd, &passwd_len,
                              &salt, &salt_len,
                              &opslimit, &memlimit) == FAILURE ||
        hash_len <= 0 || hash_len >= STRSIZE_MAX ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_pwhash_scryptsalsa208sha256(): invalid parameters", 0);
        return;
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (salt_len != crypto_pwhash_scryptsalsa208sha256_SALTBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "salt should be CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES bytes",
                   0);
        return;
    }
    if (opslimit < crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()) {
        zend_error(E_WARNING,
                   "number of operations for the scrypt function is low");
    }
    if (memlimit < crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()) {
        zend_error(E_WARNING,
                   "maximum memory for the scrypt function is low");
    }
    hash = zend_string_alloc((size_t) hash_len, 0);
    if (crypto_pwhash_scryptsalsa208sha256
        ((unsigned char *) ZSTR_VAL(hash), (unsigned long long) hash_len,
         passwd, (unsigned long long) passwd_len, salt,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        zend_string_free(hash);
        zend_throw_exception(zend_ce_error, "crypto_pwhash_scryptsalsa208sha256(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash)[hash_len] = 0;

    RETURN_STR(hash);
}

PHP_FUNCTION(sodium_crypto_pwhash_scryptsalsa208sha256_str)
{
    zend_string *hash_str;
    char        *passwd;
    zend_long    memlimit;
    zend_long    opslimit;
    strsize_t    passwd_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll",
                              &passwd, &passwd_len,
                              &opslimit, &memlimit) == FAILURE ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_pwhash_scryptsalsa208sha256_str(): invalid parameters",
                   0);
        return;
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (opslimit < crypto_pwhash_scryptsalsa208sha256_opslimit_interactive()) {
        zend_error(E_WARNING,
                   "number of operations for the scrypt function is low");
    }
    if (memlimit < crypto_pwhash_scryptsalsa208sha256_memlimit_interactive()) {
        zend_error(E_WARNING,
                   "maximum memory for the scrypt function is low");
    }
    hash_str = zend_string_alloc
        (crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1, 0);
    if (crypto_pwhash_scryptsalsa208sha256_str
        (ZSTR_VAL(hash_str), passwd, (unsigned long long) passwd_len,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        zend_string_free(hash_str);
        zend_throw_exception(zend_ce_error, "crypto_pwhash_scryptsalsa208sha256_str(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash_str)[crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1] = 0;

    RETURN_STR(hash_str);
}

PHP_FUNCTION(sodium_crypto_pwhash_scryptsalsa208sha256_str_verify)
{
    char      *hash_str;
    char      *passwd;
    strsize_t  hash_str_len;
    strsize_t  passwd_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &hash_str, &hash_str_len,
                              &passwd, &passwd_len) == FAILURE) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_pwhash_scryptsalsa208sha256_str_verify(): invalid parameters",
                   0);
        return;
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

#ifdef crypto_pwhash_SALTBYTES
PHP_FUNCTION(sodium_crypto_pwhash)
{
    zend_string   *hash;
    unsigned char *salt;
    char          *passwd;
    zend_long      hash_len;
    zend_long      memlimit;
    zend_long      opslimit;
    strsize_t      passwd_len;
    strsize_t      salt_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lssll",
                              &hash_len,
                              &passwd, &passwd_len,
                              &salt, &salt_len,
                              &opslimit, &memlimit) == FAILURE ||
        hash_len <= 0 || hash_len >= STRSIZE_MAX ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "crypto_pwhash(): invalid parameters", 0);
        return;
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (salt_len != crypto_pwhash_SALTBYTES) {
        zend_throw_exception(zend_ce_exception, "salt should be CRYPTO_PWHASH_SALTBYTES bytes", 0);
        return;
    }
    if (opslimit < crypto_pwhash_OPSLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "number of operations for the argon2i function is low");
    }
    if (memlimit < crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        zend_error(E_WARNING, "maximum memory for the argon2i function is low");
    }
    hash = zend_string_alloc((size_t) hash_len, 0);
    if (crypto_pwhash
        ((unsigned char *) ZSTR_VAL(hash), (unsigned long long) hash_len,
         passwd, (unsigned long long) passwd_len, salt,
         (unsigned long long) opslimit, (size_t) memlimit,
         crypto_pwhash_alg_default()) != 0) {
        zend_string_free(hash);
        zend_throw_exception(zend_ce_error, "crypto_pwhash(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash)[hash_len] = 0;

    RETURN_STR(hash);
}

PHP_FUNCTION(sodium_crypto_pwhash_str)
{
    zend_string *hash_str;
    char        *passwd;
    zend_long    memlimit;
    zend_long    opslimit;
    strsize_t    passwd_len;
    strsize_t    len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll",
                              &passwd, &passwd_len,
                              &opslimit, &memlimit) == FAILURE ||
        opslimit <= 0 || memlimit <= 0 || memlimit > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_pwhash_str(): invalid parameters",
                   0);
        return;
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (opslimit < crypto_pwhash_OPSLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "number of operations for the argon2i function is low");
    }
    if (memlimit < crypto_pwhash_MEMLIMIT_INTERACTIVE) {
        zend_error(E_WARNING,
                   "maximum memory for the argon2i function is low");
    }
    hash_str = zend_string_alloc(crypto_pwhash_STRBYTES - 1, 0);
    if (crypto_pwhash_str
        (ZSTR_VAL(hash_str), passwd, (unsigned long long) passwd_len,
         (unsigned long long) opslimit, (size_t) memlimit) != 0) {
        zend_string_free(hash_str);
        zend_throw_exception(zend_ce_error, "crypto_pwhash_str(): internal error", 0);
        return;
    }
    ZSTR_VAL(hash_str)[crypto_pwhash_STRBYTES - 1] = 0;

    len = strlen(ZSTR_VAL(hash_str));
    ZSTR_TRUNCATE(hash_str, len);

    RETURN_STR(hash_str);
}

PHP_FUNCTION(sodium_crypto_pwhash_str_verify)
{
    char      *hash_str;
    char      *passwd;
    strsize_t  hash_str_len;
    strsize_t  passwd_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &hash_str, &hash_str_len,
                              &passwd, &passwd_len) == FAILURE) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_pwhash_str_verify(): invalid parameters",
                   0);
        return;
    }
    if (passwd_len <= 0) {
        zend_error(E_WARNING, "empty password");
    }
    if (crypto_pwhash_str_verify
        (hash_str, passwd, (unsigned long long) passwd_len) == 0) {
        RETURN_TRUE;
    }
    RETURN_FALSE;
}
#endif

PHP_FUNCTION(sodium_crypto_aead_aes256gcm_is_available)
{
#ifdef HAVE_AESGCM
    RETURN_BOOL(crypto_aead_aes256gcm_is_available());
#else
    RETURN_FALSE;
#endif
}

#ifdef HAVE_AESGCM
PHP_FUNCTION(sodium_crypto_aead_aes256gcm_encrypt)
{
    zend_string        *ciphertext;
    unsigned char      *ad;
    unsigned char      *msg;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  ciphertext_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &msg, &msg_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_aes256gcm_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_aes256gcm_encrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_aes256gcm_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_aes256gcm_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_aes256gcm_encrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_aes256gcm_KEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_aead_aes256gcm_ABYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext_len = msg_len + crypto_aead_aes256gcm_ABYTES;
    ciphertext = zend_string_alloc((size_t) ciphertext_len, 0);
    if (crypto_aead_aes256gcm_encrypt
        ((unsigned char *) ZSTR_VAL(ciphertext), &ciphertext_real_len, msg,
         (unsigned long long) msg_len,
         ad, (unsigned long long) ad_len, NULL, npub, secretkey) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_aead_aes256gcm_encrypt(): internal error", 0);
        return;
    }
    if (ciphertext_real_len <= 0U || ciphertext_real_len >= STRSIZE_MAX ||
        ciphertext_real_len > ciphertext_len) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(ciphertext, (strsize_t) ciphertext_real_len);
    ZSTR_VAL(ciphertext)[ciphertext_real_len] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_aead_aes256gcm_decrypt)
{
    zend_string        *msg;
    unsigned char      *ad;
    unsigned char      *ciphertext;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  msg_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &ciphertext, &ciphertext_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_aes256gcm_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_aes256gcm_decrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_aes256gcm_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_aes256gcm_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_aes256gcm_decrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_aes256gcm_KEYBYTES bytes",
                   0);
        return;
    }
    msg_len = ciphertext_len;
    if (msg_len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    msg = zend_string_alloc((size_t) msg_len, 0);
    if (ciphertext_len < crypto_aead_aes256gcm_ABYTES ||
        crypto_aead_aes256gcm_decrypt
        ((unsigned char *) ZSTR_VAL(msg), &msg_real_len, NULL,
         ciphertext, (unsigned long long) ciphertext_len,
         ad, (unsigned long long) ad_len, npub, secretkey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    }
    if (msg_real_len >= STRSIZE_MAX || msg_real_len > msg_len) {
        zend_string_free(msg);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(msg, (strsize_t) msg_real_len);
    ZSTR_VAL(msg)[msg_real_len] = 0;

    RETURN_STR(msg);
}
#endif

PHP_FUNCTION(sodium_crypto_aead_chacha20poly1305_encrypt)
{
    zend_string        *ciphertext;
    unsigned char      *ad;
    unsigned char      *msg;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  ciphertext_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &msg, &msg_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_encrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_encrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_aead_chacha20poly1305_ABYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext_len = msg_len + crypto_aead_chacha20poly1305_ABYTES;
    ciphertext = zend_string_alloc((size_t) ciphertext_len, 0);
    if (crypto_aead_chacha20poly1305_encrypt
        ((unsigned char *) ZSTR_VAL(ciphertext), &ciphertext_real_len, msg,
         (unsigned long long) msg_len,
         ad, (unsigned long long) ad_len, NULL, npub, secretkey) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_aead_chacha20poly1305_encrypt(): internal error", 0);
        return;
    }
    if (ciphertext_real_len <= 0U || ciphertext_real_len >= STRSIZE_MAX ||
        ciphertext_real_len > ciphertext_len) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
    }
    ZSTR_TRUNCATE(ciphertext, (strsize_t) ciphertext_real_len);
    ZSTR_VAL(ciphertext)[ciphertext_real_len] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_aead_chacha20poly1305_decrypt)
{
    zend_string        *msg;
    unsigned char      *ad;
    unsigned char      *ciphertext;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  msg_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &ciphertext, &ciphertext_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_decrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_decrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES bytes",
                   0);
        return;
    }
    msg_len = ciphertext_len;
    if (msg_len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    msg = zend_string_alloc((size_t) msg_len, 0);
    if (ciphertext_len < crypto_aead_chacha20poly1305_ABYTES ||
        crypto_aead_chacha20poly1305_decrypt
        ((unsigned char *) ZSTR_VAL(msg), &msg_real_len, NULL,
         ciphertext, (unsigned long long) ciphertext_len,
         ad, (unsigned long long) ad_len, npub, secretkey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    }
    if (msg_real_len >= STRSIZE_MAX || msg_real_len > msg_len) {
        zend_string_free(msg);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
    }
    ZSTR_TRUNCATE(msg, (strsize_t) msg_real_len);
    ZSTR_VAL(msg)[msg_real_len] = 0;

    RETURN_STR(msg);
}

#ifdef crypto_aead_chacha20poly1305_IETF_NPUBBYTES
PHP_FUNCTION(sodium_crypto_aead_chacha20poly1305_ietf_encrypt)
{
    zend_string        *ciphertext;
    unsigned char      *ad;
    unsigned char      *msg;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  ciphertext_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &msg, &msg_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_IETF_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_ietf_encrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_ietf_encrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES bytes",
                   0);
        return;
    }
    if (STRSIZE_MAX - msg_len <= crypto_aead_chacha20poly1305_ABYTES) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    if ((unsigned long long) msg_len > 64ULL * (1ULL << 32) - 64ULL) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ciphertext_len = msg_len + crypto_aead_chacha20poly1305_ABYTES;
    ciphertext = zend_string_alloc((size_t) ciphertext_len, 0);
    if (crypto_aead_chacha20poly1305_ietf_encrypt
        ((unsigned char *) ZSTR_VAL(ciphertext), &ciphertext_real_len, msg,
         (unsigned long long) msg_len,
         ad, (unsigned long long) ad_len, NULL, npub, secretkey) != 0) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_error, "crypto_aead_chacha20poly1305_ietf_encrypt(): internal error", 0);
        return;
    }
    if (ciphertext_real_len <= 0U || ciphertext_real_len >= STRSIZE_MAX ||
        ciphertext_real_len > ciphertext_len) {
        zend_string_free(ciphertext);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(ciphertext, (strsize_t) ciphertext_real_len);
    ZSTR_VAL(ciphertext)[ciphertext_real_len] = 0;

    RETURN_STR(ciphertext);
}

PHP_FUNCTION(sodium_crypto_aead_chacha20poly1305_ietf_decrypt)
{
    zend_string        *msg;
    unsigned char      *ad;
    unsigned char      *ciphertext;
    unsigned char      *npub;
    unsigned char      *secretkey;
    unsigned long long  msg_real_len;
    strsize_t           ad_len;
    strsize_t           ciphertext_len;
    strsize_t           msg_len;
    strsize_t           npub_len;
    strsize_t           secretkey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &ciphertext, &ciphertext_len,
                              &ad, &ad_len,
                              &npub, &npub_len,
                              &secretkey, &secretkey_len) == FAILURE) {
        return;
    }
    if (npub_len != crypto_aead_chacha20poly1305_IETF_NPUBBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_ietf_decrypt(): "
                   "public nonce size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES bytes",
                   0);
        return;
    }
    if (secretkey_len != crypto_aead_chacha20poly1305_KEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_aead_chacha20poly1305_ietf_decrypt(): "
                   "secret key size should be "
                   "CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES bytes",
                   0);
        return;
    }
    msg_len = ciphertext_len;
    if (msg_len >= STRSIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    if ((unsigned long long) ciphertext_len -
        crypto_aead_chacha20poly1305_ABYTES > 64ULL * (1ULL << 32) - 64ULL) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    msg = zend_string_alloc((size_t) msg_len, 0);
    if (ciphertext_len < crypto_aead_chacha20poly1305_ABYTES ||
        crypto_aead_chacha20poly1305_ietf_decrypt
        ((unsigned char *) ZSTR_VAL(msg), &msg_real_len, NULL,
         ciphertext, (unsigned long long) ciphertext_len,
         ad, (unsigned long long) ad_len, npub, secretkey) != 0) {
        zend_string_free(msg);
        RETURN_FALSE;
    }
    if (msg_real_len >= STRSIZE_MAX || msg_real_len > msg_len) {
        zend_string_free(msg);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(msg, (strsize_t) msg_real_len);
    ZSTR_VAL(msg)[msg_real_len] = 0;

    RETURN_STR(msg);
}
#endif

PHP_FUNCTION(sodium_bin2hex)
{
    zend_string   *hex;
    unsigned char *bin;
    strsize_t      bin_len;
    strsize_t      hex_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &bin, &bin_len) == FAILURE) {
        return;
    }
    if (bin_len >= STRSIZE_MAX / 2U) {
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    hex_len = bin_len * 2U;
    hex = zend_string_alloc((size_t) hex_len, 0);
    sodium_bin2hex(ZSTR_VAL(hex), hex_len + 1U, bin, bin_len);
    ZSTR_VAL(hex)[hex_len] = 0;

    RETURN_STR(hex);
}

PHP_FUNCTION(sodium_hex2bin)
{
    zend_string   *bin;
    char          *hex;
    char          *ignore = NULL;
    size_t         bin_real_len;
    size_t         bin_len;
    strsize_t      hex_len;
    strsize_t      ignore_len = 0;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|s",
                              &hex, &hex_len,
                              &ignore, &ignore_len) == FAILURE) {
        return;
    }
    bin_len = hex_len / 2;
    bin = zend_string_alloc(bin_len, 0);
    if (sodium_hex2bin((unsigned char *) ZSTR_VAL(bin), bin_len, hex, hex_len,
                       ignore, &bin_real_len, NULL) != 0 ||
        bin_real_len >= STRSIZE_MAX || bin_real_len > bin_len) {
        zend_string_free(bin);
        zend_throw_exception(zend_ce_exception, "arithmetic overflow", 0);
        return;
    }
    ZSTR_TRUNCATE(bin, (strsize_t) bin_real_len);
    ZSTR_VAL(bin)[bin_real_len] = 0;

    RETURN_STR(bin);
}

PHP_FUNCTION(sodium_crypto_scalarmult)
{
    zend_string   *q;
    unsigned char *n;
    unsigned char *p;
    strsize_t      n_len;
    strsize_t      p_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &n, &n_len, &p, &p_len) == FAILURE) {
        return;
    }
    if (n_len != crypto_scalarmult_SCALARBYTES ||
        p_len != crypto_scalarmult_SCALARBYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_scalarmult(): scalar and point must be "
                   "CRYPTO_SCALARMULT_SCALARBYTES bytes",
                   0);
        return;
    }
    q = zend_string_alloc(crypto_scalarmult_BYTES, 0);
    if (crypto_scalarmult((unsigned char *) ZSTR_VAL(q), n, p) != 0) {
        zend_string_free(q);
        zend_throw_exception(zend_ce_error, "crypto_scalarmult(): internal error", 0);
        return;
    }
    ZSTR_VAL(q)[crypto_scalarmult_BYTES] = 0;

    RETURN_STR(q);
}

PHP_FUNCTION(sodium_crypto_kx)
{
    crypto_generichash_state h;
    unsigned char            q[crypto_scalarmult_BYTES];
    zend_string             *sharedkey;
    unsigned char           *client_publickey;
    unsigned char           *publickey;
    unsigned char           *secretkey;
    unsigned char           *server_publickey;
    strsize_t                client_publickey_len;
    strsize_t                publickey_len;
    strsize_t                secretkey_len;
    strsize_t                server_publickey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ssss",
                              &secretkey, &secretkey_len,
                              &publickey, &publickey_len,
                              &client_publickey, &client_publickey_len,
                              &server_publickey, &server_publickey_len) == FAILURE) {
        return;
    }
    if (secretkey_len != crypto_kx_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_kx(): secret key must be CRYPTO_KX_SECRETKEY bytes", 0);
        return;
    }
    if (publickey_len != crypto_kx_PUBLICKEYBYTES ||
        client_publickey_len != crypto_kx_PUBLICKEYBYTES ||
        server_publickey_len != crypto_kx_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_kx(): public keys must be CRYPTO_KX_PUBLICKEY bytes", 0);
        return;
    }
    (void) sizeof(int[crypto_scalarmult_SCALARBYTES ==
                      crypto_kx_PUBLICKEYBYTES ? 1 : -1]);
    (void) sizeof(int[crypto_scalarmult_SCALARBYTES ==
                      crypto_kx_SECRETKEYBYTES ? 1 : -1]);
    if (crypto_scalarmult(q, secretkey, publickey) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_kx(): internal error", 0);
        return;
    }
    sharedkey = zend_string_alloc(crypto_kx_BYTES, 0);
    crypto_generichash_init(&h, NULL, 0U, crypto_generichash_BYTES);
    crypto_generichash_update(&h, q, sizeof q);
    sodium_memzero(q, sizeof q);
    crypto_generichash_update(&h, client_publickey, client_publickey_len);
    crypto_generichash_update(&h, server_publickey, server_publickey_len);
    crypto_generichash_final(&h, (unsigned char *) ZSTR_VAL(sharedkey),
                             crypto_kx_BYTES);
    ZSTR_VAL(sharedkey)[crypto_kx_BYTES] = 0;

    RETURN_STR(sharedkey);
}

PHP_FUNCTION(sodium_crypto_auth)
{
    zend_string *mac;
    char        *key;
    char        *msg;
    strsize_t    msg_len;
    strsize_t    key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &msg, &msg_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (key_len != crypto_auth_KEYBYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_auth(): key must be CRYPTO_AUTH_KEYBYTES bytes", 0);
        return;
    }
    mac = zend_string_alloc(crypto_auth_BYTES, 0);
    if (crypto_auth((unsigned char *) ZSTR_VAL(mac),
                    (const unsigned char *) msg, msg_len,
                    (const unsigned char *) key) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_auth(): internal error", 0);
        return;
    }
    ZSTR_VAL(mac)[crypto_auth_BYTES] = 0;

    RETURN_STR(mac);
}

PHP_FUNCTION(sodium_crypto_auth_verify)
{
    char      *mac;
    char      *key;
    char      *msg;
    strsize_t  mac_len;
    strsize_t  msg_len;
    strsize_t  key_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss",
                              &mac, &mac_len,
                              &msg, &msg_len,
                              &key, &key_len) == FAILURE) {
        return;
    }
    if (key_len != crypto_auth_KEYBYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_auth_verify(): key must be CRYPTO_AUTH_KEYBYTES bytes", 0);
        return;
    }
    if (mac_len != crypto_auth_BYTES) {
        zend_throw_exception(zend_ce_exception, "crypto_auth_verify(): authentication tag must be CRYPTO_AUTH_BYTES bytes", 0);
        return;
    }
    if (crypto_auth_verify((const unsigned char *) mac,
                           (const unsigned char *) msg, msg_len,
                           (const unsigned char *) key) != 0) {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_FUNCTION(sodium_crypto_sign_ed25519_sk_to_curve25519)
{
    zend_string *ecdhkey;
    char        *eddsakey;
    strsize_t    eddsakey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &eddsakey, &eddsakey_len) == FAILURE) {
        return;
    }
    if (eddsakey_len != crypto_sign_SECRETKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_ed25519_sk_to_curve25519(): "
                   "Ed25519 key should be CRYPTO_SIGN_SECRETKEYBYTES long",
                   0);
        return;
    }
    ecdhkey = zend_string_alloc(crypto_box_SECRETKEYBYTES, 0);

    if (crypto_sign_ed25519_sk_to_curve25519((unsigned char *) ZSTR_VAL(ecdhkey),
                                             (const unsigned char *) eddsakey) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_sign_ed25519_sk_to_curve25519()", 0);
        return;
    }
    ZSTR_VAL(ecdhkey)[crypto_box_SECRETKEYBYTES] = 0;

    RETURN_STR(ecdhkey);
}

PHP_FUNCTION(sodium_crypto_sign_ed25519_pk_to_curve25519)
{
    zend_string *ecdhkey;
    char        *eddsakey;
    strsize_t    eddsakey_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s",
                              &eddsakey, &eddsakey_len) == FAILURE) {
        return;
    }
    if (eddsakey_len != crypto_sign_PUBLICKEYBYTES) {
        zend_throw_exception(zend_ce_exception,
                   "crypto_sign_ed25519_pk_to_curve25519(): "
                   "Ed25519 key should be CRYPTO_SIGN_PUBLICKEYBYTES long",
                   0);
        return;
    }
    ecdhkey = zend_string_alloc(crypto_sign_PUBLICKEYBYTES, 0);

    if (crypto_sign_ed25519_pk_to_curve25519((unsigned char *) ZSTR_VAL(ecdhkey),
                                             (const unsigned char *) eddsakey) != 0) {
        zend_throw_exception(zend_ce_error, "crypto_sign_ed25519_pk_to_curve25519()", 0);
    }
    ZSTR_VAL(ecdhkey)[crypto_box_PUBLICKEYBYTES] = 0;

    RETURN_STR(ecdhkey);
}

#if SODIUM_LIBRARY_VERSION_MAJOR > 7 || \
    (SODIUM_LIBRARY_VERSION_MAJOR == 7 && SODIUM_LIBRARY_VERSION_MINOR >= 6)
PHP_FUNCTION(sodium_compare)
{
    char      *buf1;
    char      *buf2;
    strsize_t  len1;
    strsize_t  len2;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss",
                              &buf1, &len1,
                              &buf2, &len2) == FAILURE) {
        return;
    }
    if (len1 != len2) {
        zend_throw_exception(zend_ce_exception, "compare(): arguments have different sizes", 0);
    } else if (len1 > SIZE_MAX) {
        zend_throw_exception(zend_ce_exception, "compare(): invalid length", 0);
    } else {
        RETURN_LONG(sodium_compare((const unsigned char *) buf1,
                                   (const unsigned char *) buf2, (size_t) len1));
    }
}
#endif
