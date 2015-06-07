--TEST--
Check for libsodium stream AES-128-CTR
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php

define('COUNTER_BYTES', 4);
define('BLOCK_BYTES', 16);

function incrementCounter($nonce, $offset)
{
	$value = unpack('N', substr($nonce, -COUNTER_BYTES));
	$value = $value[1] + $offset;
	return substr($nonce, 0, -COUNTER_BYTES) . pack('N', $value);
}

function resetCounter($nonce)
{
	return substr($nonce, 0, -COUNTER_BYTES) . str_repeat(chr(0), COUNTER_BYTES);
}

$nonce = resetCounter(Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_NONCEBYTES));
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_KEYBYTES);

$len = 100;
$stream = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);
var_dump(strlen($stream));

$stream2 = Sodium::crypto_stream_aes128ctr($len, $nonce, $key);

$nonce = resetCounter(Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_AES128CTR_NONCEBYTES));
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

$originalSection = substr($stream, 32, 32);
$encryptedSection = substr($stream5, 32, 32);

$incrementedNonce = incrementCounter($nonce, 32 / BLOCK_BYTES);
$decryptedSection = Sodium::crypto_stream_aes128ctr_xor($encryptedSection, $incrementedNonce, $key);
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
