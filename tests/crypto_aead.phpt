--TEST--
Check for libsodium AEAD
--SKIPIF--
<?php
if (!extension_loaded("libsodium")) print "skip extension not loaded";
if (!defined('SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES')) print "skip libsodium without AESGCM";
?>
--FILE--
<?php
$msg = sodium_randombytes_buf(sodium_randombytes_uniform(1000));
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
$ad = sodium_randombytes_buf(sodium_randombytes_uniform(1000));

$ciphertext = sodium_crypto_aead_chacha20poly1305_encrypt($msg, $ad, $nonce, $key);
$msg2 = sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $ad, $nonce, $key);
var_dump($ciphertext !== $msg);
var_dump($msg === $msg2);
var_dump(sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, 'x' . $ad, $nonce, $key));

$msg = sodium_randombytes_buf(sodium_randombytes_uniform(1000));
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES);
$ad = sodium_randombytes_buf(sodium_randombytes_uniform(1000));

if (sodium_library_version_major() > 7 ||
    (sodium_library_version_major() == 7 &&
     sodium_library_version_minor() >= 6)) {
    $ciphertext = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($msg, $ad, $nonce, $key);
    $msg2 = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $ad, $nonce, $key);
    var_dump($ciphertext !== $msg);
    var_dump($msg === $msg2);
    var_dump(sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, 'x' . $ad, $nonce, $key));
    try {
        // Switched order
        $msg2 = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $ad, $key, $nonce);
        var_dump(false);
    } catch (SodiumException $ex) {
        var_dump(true);
    }
} else {
    var_dump(true);
    var_dump(true);
    var_dump(false);
}

$msg = sodium_randombytes_buf(sodium_randombytes_uniform(1000));
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
$ad = sodium_randombytes_buf(sodium_randombytes_uniform(1000));

if (sodium_crypto_aead_aes256gcm_is_available()) {
    $ciphertext = sodium_crypto_aead_aes256gcm_encrypt($msg, $ad, $nonce, $key);
    $msg2 = sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $ad, $nonce, $key);
    var_dump($ciphertext !== $msg);
    var_dump($msg === $msg2);
    var_dump(sodium_crypto_aead_aes256gcm_decrypt($ciphertext, 'x' . $ad, $nonce, $key));
} else {
    var_dump(true);
    var_dump(true);
    var_dump(false);
}
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(true)
bool(false)
