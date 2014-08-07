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
?>
--EXPECT--
0
bool(true)
bool(false)
