--TEST--
Check for libsodium randombytes
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = \Sodium\randombytes_buf(100);
echo strlen($a);
echo "\n";
$b = \Sodium\randombytes_buf(100);
echo strlen($a);
echo "\n";
if ($a === $b) {
  echo "Fail\n";
} else {
  echo "OK\n";
}
$x = 10;
$c = \Sodium\randombytes_random16();
while (\Sodium\randombytes_random16() === $c) {
  if (--$x <= 0) {
    die("FAIL\n");
  }
}
echo "OK\n";
$x = 10000;
do {
  $c = \Sodium\randombytes_random16();
  if ($c < 0 || $c > 0xffff) {
    die("FAIL\n");
  }
} while (--$x > 0);
echo "OK\n";
$d = \Sodium\randombytes_uniform(10);
if ($d < 10) {
  echo "OK\n";
}
?>
--EXPECT--
100
100
OK
OK
OK
OK
