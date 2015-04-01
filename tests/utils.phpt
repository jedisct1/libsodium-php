--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = 'test';
Sodium::sodium_memzero($a);
if ($a !== 'test') {
  echo strlen($a);
} else {
  echo $a;
}
echo "\n";
$b = 'string';
$c = 'string';
var_dump(!Sodium::sodium_memcmp($b, $c));
var_dump(!Sodium::sodium_memcmp($b, 'String'));
$x = Sodium::sodium_hex2bin('48-2C-6A-1E-59-3D');
var_dump(($x === "\x48\x2C\x6A\x1E\x59\x3D"));
var_dump((Sodium::sodium_bin2hex($x) === '482c6a1e493d'));
var_dump((Sodium::sodium_bin2hex($x) === '1e493d482c6a'));
?>
--EXPECT--
0
bool(true)
bool(false)
bool(true)
bool(true)
bool(false)
