--TEST--
Check for libsodium stream
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_NONCEBYTES);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_KEYBYTES);

$a = Sodium::crypto_stream_xor('test', $nonce, $key);
$x = Sodium::crypto_stream_xor($a, $nonce, $key);
var_dump(bin2hex($x));

?>
--EXPECT--
string(8) "74657374"

