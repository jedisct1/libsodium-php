--TEST--
Check for libsodium ed25519 signatures
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = Sodium::crypto_sign_keypair();
var_dump(strlen($keypair) === Sodium::CRYPTO_SIGN_KEYPAIRBYTES);
$sk = Sodium::crypto_sign_secretkey($keypair);
var_dump(strlen($sk) === Sodium::CRYPTO_SIGN_SECRETKEYBYTES);
$pk = Sodium::crypto_sign_publickey($keypair);
var_dump(strlen($pk) === Sodium::CRYPTO_SIGN_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$keypair2 = Sodium::crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk);
var_dump($keypair === $keypair2);

$alice_kp = Sodium::crypto_sign_keypair();
$alice_secretkey = Sodium::crypto_sign_secretkey($alice_kp);
$alice_publickey = Sodium::crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

$msg_signed = Sodium::crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === Sodium::CRYPTO_SIGN_BYTES);

$msg_orig = Sodium::crypto_sign_open($msg_signed, $alice_publickey);
var_dump($msg_orig === $msg);

$seed = str_repeat('x', Sodium::CRYPTO_SIGN_SEEDBYTES);
$alice_kp = Sodium::crypto_sign_seed_keypair($seed);

$alice_secretkey = Sodium::crypto_sign_secretkey($alice_kp);
$alice_publickey = Sodium::crypto_sign_publickey($alice_kp);

$msg = "Here is another message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key, which will be always the same " .
  "since they are derived from a fixed seed";

$msg_signed = Sodium::crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === Sodium::CRYPTO_SIGN_BYTES);

$msg_orig = Sodium::crypto_sign_open($msg_signed, $alice_publickey);
var_dump($msg_orig === $msg);

?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
