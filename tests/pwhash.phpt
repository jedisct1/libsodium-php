--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$passwd = 'test';

$hash = Sodium::crypto_pwhash_scryptsalsa208sha256_str
  ($passwd, CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
var_dump(substr($hash, 0, 3) ===
         CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX);

$c = Sodium::crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $passwd);
var_dump($c);

$c = Sodium::crypto_pwhash_scryptsalsa208sha256_str_verify($hash, 'passwd');
var_dump($c);

$salt = Sodium::randombytes_buf(CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);
$out_len = 100;
$key = Sodium::crypto_pwhash_scryptsalsa208sha256
  ($out_len, $passwd, $salt,
   CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
   CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
var_dump(strlen($key) === $out_len);
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
