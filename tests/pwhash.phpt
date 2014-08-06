--TEST--
Check for libsodium utils
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$pwd = 'test';

$hash = crypto_pwhash_scryptsalsa208sha256_str
  ($pwd, CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
         CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);
var_dump(substr($hash, 0, 3) ===
         CRYPTO_PWHASH_SCRYPTSALSA208SHA256_STRPREFIX);

$c = crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $pwd);
var_dump($c);

$c = crypto_pwhash_scryptsalsa208sha256_str_verify($hash, 'pwd');
var_dump($c);
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
