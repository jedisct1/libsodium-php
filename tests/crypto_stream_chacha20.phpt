--TEST--
Check for libsodium stream ChaCha20
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_CHACHA20_NONCEBYTES);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_CHACHA20_KEYBYTES);

$len = 100;
$stream = Sodium::crypto_stream_chacha20($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = Sodium::crypto_stream_chacha20($len, $nonce, $key);

$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_CHACHA20_NONCEBYTES);
$stream3 = Sodium::crypto_stream_chacha20($len, $nonce, $key);

$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_CHACHA20_KEYBYTES);
$stream4 = Sodium::crypto_stream_chacha20($len, $nonce, $key);

var_dump($stream === $stream2);
var_dump($stream !== $stream3);
var_dump($stream !== $stream4);
var_dump($stream2 !== $stream3);
var_dump($stream2 !== $stream4);
var_dump($stream3 !== $stream4);

$stream5 = Sodium::crypto_stream_chacha20_xor($stream, $nonce, $key);
var_dump($stream5 !== $stream);
$stream6 = Sodium::crypto_stream_chacha20_xor($stream5, $nonce, $key);

var_dump($stream6 === $stream);

$stream7 = Sodium::crypto_stream_salsa20_xor_ic($stream, $nonce, 8, $key);
var_dump($stream7 !== $stream);
$stream8 = Sodium::crypto_stream_salsa20_xor_ic($stream7, $nonce, 8, $key);
var_dump($stream8 === $stream);
$stream9 = Sodium::crypto_stream_salsa20_xor_ic($stream7, $nonce, 9, $key);
var_dump($stream9 !== $stream);

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
bool(true)
bool(true)
