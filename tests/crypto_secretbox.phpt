--TEST--
Check for libsodium secretbox
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$nonce = '0123456789abcdef01234567';
$key = '0123456789abcdef0123456789abcdef';

$a = crypto_secretbox('test', $nonce, $key);
$x = crypto_secretbox_open($a, $nonce, $key);
var_dump(bin2hex($x));
$y = crypto_secretbox_open("\0" . $a, $nonce, $key);
var_dump($y);
?>
--EXPECT--
string(8) "74657374"
bool(false)
