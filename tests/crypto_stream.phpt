--TEST--
Check for libsodium stream
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_NONCEBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_KEYBYTES);

$len = 100;
$stream = sodium_crypto_stream($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = sodium_crypto_stream($len, $nonce, $key);

$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_NONCEBYTES);
$stream3 = sodium_crypto_stream($len, $nonce, $key);

$key = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_KEYBYTES);
$stream4 = sodium_crypto_stream($len, $nonce, $key);

var_dump($stream === $stream2);
var_dump($stream !== $stream3);
var_dump($stream !== $stream4);
var_dump($stream2 !== $stream3);
var_dump($stream2 !== $stream4);
var_dump($stream3 !== $stream4);

$stream5 = sodium_crypto_stream_xor($stream, $nonce, $key);
var_dump($stream5 !== $stream);
$stream6 = sodium_crypto_stream_xor($stream5, $nonce, $key);

var_dump($stream6 === $stream);

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
