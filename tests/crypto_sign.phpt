--TEST--
Check for libsodium ed25519 signatures
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = crypto_sign_keypair();
var_dump(strlen($keypair) === CRYPTO_SIGN_KEYPAIRBYTES);
$sk = crypto_sign_secretkey($keypair);
var_dump(strlen($sk) === CRYPTO_SIGN_SECRETKEYBYTES);
$pk = crypto_sign_publickey($keypair);
var_dump(strlen($pk) === CRYPTO_SIGN_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$keypair2 = crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk);
var_dump($keypair === $keypair2);

$alice_kp = crypto_sign_keypair();
$alice_secretkey = crypto_sign_secretkey($alice_kp);
$alice_publickey = crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

$msg_signed = crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === CRYPTO_SIGN_BYTES);

$msg_orig = crypto_sign_open($msg_signed, $alice_publickey);
var_dump($msg_orig === $msg);

$seed = str_repeat('x', CRYPTO_SIGN_SEEDBYTES);
$alice_kp = crypto_sign_seed_keypair($seed);

$alice_secretkey = crypto_sign_secretkey($alice_kp);
$alice_publickey = crypto_sign_publickey($alice_kp);

$msg = "Here is another message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key, which will be always the same " .
  "since they are derived from a fixed seed";

$msg_signed = crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === CRYPTO_SIGN_BYTES);

$msg_orig = crypto_sign_open($msg_signed, $alice_publickey);
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
