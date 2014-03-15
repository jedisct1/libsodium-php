--TEST--
Check for libsodium randombytes
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$a = randombytes_buf(100);
echo strlen($a);
echo "\n";
$b = randombytes_buf(100);
echo strlen($a);
echo "\n";
if ($a === $b) {
  echo "Fail\n";
} else {
  echo "OK\n";
}
$x = 10;
$c = randombytes_random16();
while (randombytes_random16() === $c) {
  if (--$x <= 0) {
    die("FAIL\n");
  }
}
echo "OK\n";
$d = randombytes_uniform(10);
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
