--TEST--
Check for libsodium scalarmult
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$n = "Scalar to multiply the point by.";
$p = "The point, as a 32 bytes string.";
$q = Sodium::crypto_scalarmult($n, $p);

var_dump(Sodium::sodium_bin2hex($q));
?>
--EXPECT--
string(64) "45ae0f8bc38036d63b9f507b4ff9766962ff538baa1e436181915a9f27536d72"
