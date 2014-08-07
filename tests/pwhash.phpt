--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$passwd = 'test';

$hash = Sodium::crypto_pwhash_scryptsalsa208sha256_str
  ($passwd, Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
var_dump(substr($hash, 0, 3) ===
         Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX);

$c = Sodium::crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $passwd);
var_dump($c);

$c = Sodium::crypto_pwhash_scryptsalsa208sha256_str_verify($hash, 'passwd');
var_dump($c);

$salt = Sodium::randombytes_buf(Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);
$out_len = 100;
$key = Sodium::crypto_pwhash_scryptsalsa208sha256
  ($out_len, $passwd, $salt,
   Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
   Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
var_dump(strlen($key) === $out_len);
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
