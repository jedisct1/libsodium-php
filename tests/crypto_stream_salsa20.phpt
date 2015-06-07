--TEST--
Check for libsodium stream Salsa20
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php

define('BLOCK_BYTES', 64);

$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_SALSA20_NONCEBYTES);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_SALSA20_KEYBYTES);

$len = 100;
$stream = Sodium::crypto_stream_salsa20($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = Sodium::crypto_stream_salsa20($len, $nonce, $key);

$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_SALSA20_NONCEBYTES);
$stream3 = Sodium::crypto_stream_salsa20($len, $nonce, $key);

$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_SALSA20_KEYBYTES);
$stream4 = Sodium::crypto_stream_salsa20($len, $nonce, $key);

var_dump($stream === $stream2);
var_dump($stream !== $stream3);
var_dump($stream !== $stream4);
var_dump($stream2 !== $stream3);
var_dump($stream2 !== $stream4);
var_dump($stream3 !== $stream4);

$stream5 = Sodium::crypto_stream_salsa20_xor($stream, $nonce, $key);
var_dump($stream5 !== $stream);
$stream6 = Sodium::crypto_stream_salsa20_xor($stream5, $nonce, $key);
var_dump($stream6 === $stream);

$originalSection = substr($stream, 64, 32);
$encryptedSection = substr($stream5, 64, 32);

$decryptedSection = Sodium::crypto_stream_salsa20_xor_ic($encryptedSection, $nonce, 64 / BLOCK_BYTES, $key);
var_dump($decryptedSection === $originalSection);

?>
--EXPECT--
int(100)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
