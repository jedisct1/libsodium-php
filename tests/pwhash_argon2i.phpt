--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
if (!defined('Sodium\CRYPTO_PWHASH_SALTBYTES')) print "skip libsodium without argon2i";
--FILE--
<?php
$passwd = 'test';

$hash = \Sodium\crypto_pwhash_str
  ($passwd, \Sodium\CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
var_dump(substr($hash, 0, 9) ===
         \Sodium\CRYPTO_PWHASH_STRPREFIX);

$testHash = '$argon2i$m=16384,t=4,p=1$RASWmfkrcH67Imu/jc5FkA$+9DuvsGgJAdVM5bQX6rc9lUGb0A9NF7sqxevXZPRKW8';
$c = \Sodium\crypto_pwhash_str_verify($testHash, $passwd);
var_dump($c);

$testHash = '$argon2i$m=16384,t=4,p=2$RASWmfkrcH67Imu/jc5FkA$+9DuvsGgJAdVM5bQX6rc9lUGb0A9NF7sqxevXZPRKW8';
$c = \Sodium\crypto_pwhash_str_verify($testHash, $passwd);
var_dump($c);

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
bool(false)
bool(true)
