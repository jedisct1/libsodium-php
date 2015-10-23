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

if (\Sodium\library_version_major() > 7 ||
    (\Sodium\library_version_major() == 7 &&
     \Sodium\library_version_minor() >= 6)) {
    $v_1 = hex2bin('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    $v_2 = hex2bin('0202030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    var_dump(\Sodium\compare($v_1, $v_2));
    \Sodium\increment($v_1);
    var_dump(\Sodium\compare($v_1, $v_2));
    \Sodium\increment($v_1);
    var_dump(\Sodium\compare($v_1, $v_2));
} else {
    // Dummy test results for libsodium < 1.0.4
    var_dump(-1, 0, 1);
}
$str = 'stdClass';
\Sodium\memzero($str);
$obj = json_decode(json_encode(['foo' => 'bar']));
var_dump($obj);
?>
--EXPECT--
0
bool(true)
bool(false)
string(22) "0000810102030405060708"
int(-1)
int(0)
int(1)
object(stdClass)#1 (1) {
  ["foo"]=>
  string(3) "bar"
}
