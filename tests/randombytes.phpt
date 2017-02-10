--TEST--
Check for libsodium randombytes
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = sodium_randombytes_buf(0);
echo strlen($a);
echo "\n";
$a = sodium_randombytes_buf(100);
echo strlen($a);
echo "\n";
$b = sodium_randombytes_buf(100);
echo strlen($a);
echo "\n";
if ($a === $b) {
  echo "Fail\n";
} else {
  echo "OK\n";
}
$x = 10;
$c = sodium_randombytes_random16();
while (sodium_randombytes_random16() === $c) {
  if (--$x <= 0) {
    die("FAIL\n");
  }
}
echo "OK\n";
$x = 10000;
do {
  $c = sodium_randombytes_random16();
  if ($c < 0 || $c > 0xffff) {
    die("FAIL\n");
  }
} while (--$x > 0);
echo "OK\n";
$d = sodium_randombytes_uniform(10);
if ($d < 10) {
  echo "OK\n";
}
?>
--EXPECT--
0
100
100
OK
OK
OK
OK
