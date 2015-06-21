--TEST--
Check for libsodium bin2hex
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$bin = \Sodium\randombytes_buf(\Sodium\randombytes_uniform(1000));
$hex = \Sodium\bin2hex($bin);
$phphex = bin2hex($bin);
var_dump(strcasecmp($hex, $phphex));

$bin2 = \Sodium\hex2bin($hex);
var_dump($bin2 === $bin);

$bin2 = \Sodium\hex2bin('[' . $hex .']', '[]');
var_dump($bin2 === $bin);
?>
--EXPECT--
int(0)
bool(true)
bool(true)
