--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = 'test';
\Sodium\memzero($a);
if ($a !== 'test') {
  echo strlen($a);
} else {
  echo $a;
}
echo "\n";
$b = 'string';
$c = 'string';
var_dump(!\Sodium\memcmp($b, $c));
var_dump(!\Sodium\memcmp($b, 'String'));
$v = hex2bin('FFFF800102030405060708');
\Sodium\increment($v);
var_dump(bin2hex($v));
?>
--EXPECT--
0
bool(true)
bool(false)
string(22) "0000810102030405060708"
