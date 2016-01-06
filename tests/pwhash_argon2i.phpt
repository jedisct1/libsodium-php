--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$passwd = 'test';

$hash = \Sodium\crypto_pwhash_str
  ($passwd, \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
var_dump(substr($hash, 0, 9) ===
         \Sodium\CRYPTO_PWHASH_STRPREFIX);

$c = \Sodium\crypto_pwhash_str_verify($hash, $passwd);
var_dump($c);

$c = \Sodium\crypto_pwhash_str_verify($hash, 'passwd');
var_dump($c);

$salt = \Sodium\randombytes_buf(\Sodium\CRYPTO_PWHASH_SALTBYTES);
$out_len = 100;
$key = \Sodium\crypto_pwhash
  ($out_len, $passwd, $salt,
   \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
   \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
var_dump(strlen($key) === $out_len);
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
