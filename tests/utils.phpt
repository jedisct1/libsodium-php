--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = 'test';
sodium_memzero($a);
if ($a !== 'test') {
  echo strlen($a);
} else {
  echo $a;
}
echo "\n";
$b = 'string';
$c = 'string';
echo sodium_memcmp($b, $c);
echo "\n";
echo sodium_memcmp($b, 'String');
echo "\n";
?>
--EXPECT--
0
0
32
