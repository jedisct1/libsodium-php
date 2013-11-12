--TEST--
Check for libsodium generichash
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$q = crypto_generichash('msg', '0123456789abcdef');
var_dump(bin2hex($q));
$q = crypto_generichash('msg', '0123456789abcdef', 64);
var_dump(bin2hex($q));
$q = crypto_generichash('msg', '0123456789abcdef0123456789abcdef', 64);
var_dump(bin2hex($q));
?>
--EXPECT--
string(64) "ba03e32a94ece425a77b350f029e0a3d37e6383158aa7cefa2b1b9470a7fcb7a"
string(128) "8ccd640462e7380010c5722d7f3c2354781d1360430197ff233509c27353fd2597c8d689bfe769467056a0655b3faba6af4e4ade248558f7c53538c4d5b94806"
string(128) "30f0e5f1e3beb7e0340976ac05a94043cce082d870e28e03c906e8fe9a88786271c6ba141eee2885e7444a870fac498cc78a13b0c53aefaec01bf38ebfe73b3f"
