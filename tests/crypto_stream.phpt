--TEST--
Check for libsodium stream
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_NONCEBYTES);
$key = Sodium::randombytes_buf(Sodium::CRYPTO_STREAM_KEYBYTES);

$a = Sodium::crypto_stream('test', $nonce, $key);
$x = Sodium::crypto_stream($a, $nonce, $key);
var_dump(bin2hex($x));
$y = Sodium::crypto_stream("\0" . $a, $nonce, $key);
var_dump($y);

?>
--EXPECT--
string(8) "74657374"
string(5) Random string
