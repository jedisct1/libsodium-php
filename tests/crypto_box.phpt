--TEST--
Check for libsodium box
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = crypto_box_keypair();
var_dump(strlen($keypair) === CRYPTO_BOX_KEYPAIRBYTES);
$sk = crypto_box_secretkey($keypair);
var_dump(strlen($sk) === CRYPTO_BOX_SECRETKEYBYTES);
$pk = crypto_box_publickey($keypair);
var_dump(strlen($pk) === CRYPTO_BOX_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$pk2 = crypto_box_publickey_from_secretkey($sk);
var_dump($pk === $pk2);
?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
