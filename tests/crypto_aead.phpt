--TEST--
Check for libsodium AEAD
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
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
?>
--EXPECT--
bool(true)
bool(true)
