--TEST--
Check for libsodium ed25519 signatures
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = sodium_crypto_sign_keypair();
var_dump(strlen($keypair) === SODIUM_CRYPTO_SIGN_KEYPAIRBYTES);
$sk = sodium_crypto_sign_secretkey($keypair);
var_dump(strlen($sk) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES);
$pk = sodium_crypto_sign_publickey($keypair);
var_dump(strlen($pk) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$keypair2 = sodium_crypto_sign_keypair_from_secretkey_and_publickey($sk, $pk);
var_dump($keypair === $keypair2);

$alice_kp = sodium_crypto_sign_keypair();
$alice_secretkey = sodium_crypto_sign_secretkey($alice_kp);
$alice_publickey = sodium_crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

$msg_signed = sodium_crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === SODIUM_CRYPTO_SIGN_BYTES);

$msg_orig = sodium_crypto_sign_open($msg_signed, $alice_publickey);
var_dump($msg_orig === $msg);

$seed = str_repeat('x', SODIUM_CRYPTO_SIGN_SEEDBYTES);
$alice_kp = sodium_crypto_sign_seed_keypair($seed);

$alice_secretkey = sodium_crypto_sign_secretkey($alice_kp);
$alice_publickey = sodium_crypto_sign_publickey($alice_kp);

$msg = "Here is another message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key, which will be always the same " .
  "since they are derived from a fixed seed";

$msg_signed = sodium_crypto_sign($msg, $alice_secretkey);
var_dump(strlen($msg_signed) - strlen($msg) === SODIUM_CRYPTO_SIGN_BYTES);

$msg_orig = sodium_crypto_sign_open($msg_signed, $alice_publickey);
var_dump($msg_orig === $msg);

$signature = sodium_crypto_sign_detached($msg, $alice_secretkey);
var_dump(strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES);
var_dump(sodium_crypto_sign_verify_detached($signature,
                                             $msg, $alice_publickey));
var_dump(sodium_crypto_sign_verify_detached($signature,
                                             $msg . "\0", $alice_publickey));
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
bool(true)
bool(true)
bool(false)
