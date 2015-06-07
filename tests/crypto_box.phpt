--TEST--
Check for libsodium box
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = sodium_crypto_box_keypair();
var_dump(strlen($keypair) === SODIUM_CRYPTO_BOX_KEYPAIRBYTES);
$sk = sodium_crypto_box_secretkey($keypair);
var_dump(strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
$pk = sodium_crypto_box_publickey($keypair);
var_dump(strlen($pk) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$pk2 = sodium_crypto_box_publickey_from_secretkey($sk);
var_dump($pk === $pk2);
$keypair2 = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, $pk);
var_dump($keypair === $keypair2);

$alice_kp = sodium_crypto_box_keypair();
$alice_secretkey = sodium_crypto_box_secretkey($alice_kp);
$alice_publickey = sodium_crypto_box_publickey($alice_kp);

$bob_kp = sodium_crypto_box_keypair();
$bob_secretkey = sodium_crypto_box_secretkey($bob_kp);
$bob_publickey = sodium_crypto_box_publickey($bob_kp);

$alice_to_bob_kp = sodium_crypto_box_keypair_from_secretkey_and_publickey
  ($alice_secretkey, $bob_publickey);

$bob_to_alice_kp = sodium_crypto_box_keypair_from_secretkey_and_publickey
  ($bob_secretkey, $alice_publickey);

$alice_to_bob_message_nonce = sodium_randombytes_buf(SODIUM_CRYPTO_BOX_NONCEBYTES);

$alice_to_bob_ciphertext = sodium_crypto_box('Hi, this is Alice',
                                              $alice_to_bob_message_nonce,
                                              $alice_to_bob_kp);

$alice_message_decrypted_by_bob = sodium_crypto_box_open($alice_to_bob_ciphertext,
                                                          $alice_to_bob_message_nonce,
                                                          $bob_to_alice_kp);

$bob_to_alice_message_nonce = sodium_randombytes_buf(SODIUM_CRYPTO_BOX_NONCEBYTES);

$bob_to_alice_ciphertext = sodium_crypto_box('Hi Alice! This is Bob',
                                              $bob_to_alice_message_nonce,
                                              $bob_to_alice_kp);

$bob_message_decrypted_by_alice = sodium_crypto_box_open($bob_to_alice_ciphertext,
                                                          $bob_to_alice_message_nonce,
                                                          $alice_to_bob_kp);

var_dump($alice_message_decrypted_by_bob);
var_dump($bob_message_decrypted_by_alice);

if (sodium_library_version_major() > 7 ||
    (sodium_library_version_major() == 7 &&
     sodium_library_version_minor() >= 5)) {
    $anonymous_message_to_alice = sodium_crypto_box_seal('Anonymous message',
                                                          $alice_publickey);

    $decrypted_message = sodium_crypto_box_seal_open($anonymous_message_to_alice,
                                                      $alice_kp);
} else {
    $decrypted_message = 'Anonymous message';
}
var_dump($decrypted_message);

?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
string(17) "Hi, this is Alice"
string(21) "Hi Alice! This is Bob"
string(17) "Anonymous message"
