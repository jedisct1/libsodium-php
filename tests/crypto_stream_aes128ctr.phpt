--TEST--
Check for libsodium stream AES-128-CTR
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_NONCEBYTES - 1) . chr(0);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_KEYBYTES);

$len = 100;
$stream = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);

$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_NONCEBYTES - 1) . chr(0);
$stream3 = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);

$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_KEYBYTES);
$stream4 = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);

var_dump($stream === $stream2);
var_dump($stream !== $stream3);
var_dump($stream !== $stream4);
var_dump($stream2 !== $stream3);
var_dump($stream2 !== $stream4);
var_dump($stream3 !== $stream4);

$stream5 = Sodium::crypto_stream_aes128ctr_xor($stream, $nonce, $key);
var_dump($stream5 !== $stream);
$stream6 = Sodium::crypto_stream_aes128ctr_xor($stream5, $nonce, $key);

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
