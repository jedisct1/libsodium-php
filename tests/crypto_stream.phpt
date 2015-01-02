--TEST--
Check for libsodium stream
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_NONCEBYTES);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_KEYBYTES);

$len = 100;
$stream = Sodium::crypto_stream($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = Sodium::crypto_stream($len, $nonce, $key);

$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_NONCEBYTES);
$stream3 = Sodium::crypto_stream($len, $nonce, $key);

$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_KEYBYTES);
$stream4 = Sodium::crypto_stream($len, $nonce, $key);

var_dump($stream == $stream2);
var_dump($stream != $stream3);
var_dump($stream != $stream4);
var_dump($stream2 != $stream3);
var_dump($stream2 != $stream4);
var_dump($stream3 != $stream4);

?>
--EXPECT--
int(100)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
