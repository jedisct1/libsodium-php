--TEST--
Check for libsodium secretbox
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);

$a = sodium_crypto_secretbox('test', $nonce, $key);
$x = sodium_crypto_secretbox_open($a, $nonce, $key);
var_dump(bin2hex($x));
$y = sodium_crypto_secretbox_open("\0" . $a, $nonce, $key);
var_dump($y);

?>
--EXPECT--
string(8) "74657374"
bool(false)
