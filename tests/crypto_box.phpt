--TEST--
Check for libsodium box
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$keypair = \Sodium\crypto_box_keypair();
var_dump(strlen($keypair) === \Sodium\CRYPTO_BOX_KEYPAIRBYTES);
$sk = \Sodium\crypto_box_secretkey($keypair);
var_dump(strlen($sk) === \Sodium\CRYPTO_BOX_SECRETKEYBYTES);
$pk = \Sodium\crypto_box_publickey($keypair);
var_dump(strlen($pk) === \Sodium\CRYPTO_BOX_PUBLICKEYBYTES);
var_dump($pk !== $sk);
$pk2 = \Sodium\crypto_box_publickey_from_secretkey($sk);
var_dump($pk === $pk2);
$pk2 = \Sodium\crypto_scalarmult_base($sk);
var_dump($pk === $pk2);
$keypair2 = \Sodium\crypto_box_keypair_from_secretkey_and_publickey($sk, $pk);
var_dump($keypair === $keypair2);

$seed_x = str_repeat('x', \Sodium\CRYPTO_BOX_SEEDBYTES);
$seed_y = str_repeat('y', \Sodium\CRYPTO_BOX_SEEDBYTES);
$alice_box_kp = \Sodium\crypto_box_seed_keypair($seed_x);
$bob_box_kp = \Sodium\crypto_box_seed_keypair($seed_y);
$message_nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_NONCEBYTES);

$alice_box_secretkey = \Sodium\crypto_box_secretkey($alice_box_kp);
$bob_box_publickey = \Sodium\crypto_box_publickey($bob_box_kp);

$alice_to_bob_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
    $alice_box_secretkey,
    $bob_box_publickey
);

$msg = "Here is another message, to be signed using Alice's secret key, and " .
  "to be encrypted using Bob's public key. The keys will always be the same " .
  "since they are derived from a fixed seeds";

$ciphertext = \Sodium\crypto_box(
    $msg,
    $message_nonce,
    $alice_to_bob_kp
);

\Sodium\memzero($alice_box_kp);
\Sodium\memzero($bob_box_kp);

$alice_box_kp = \Sodium\crypto_box_seed_keypair($seed_x);
$bob_box_kp = \Sodium\crypto_box_seed_keypair($seed_y);

$alice_box_publickey = \Sodium\crypto_box_publickey($alice_box_kp);
$bob_box_secretkey = \Sodium\crypto_box_secretkey($bob_box_kp);

$bob_to_alice_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
    $bob_box_secretkey,
    $alice_box_publickey
);

$plaintext = \Sodium\crypto_box_open(
    $ciphertext,
    $message_nonce,
    $bob_to_alice_kp
);

var_dump($msg === $plaintext);

$alice_kp = \Sodium\crypto_box_keypair();
$alice_secretkey = \Sodium\crypto_box_secretkey($alice_kp);
$alice_publickey = \Sodium\crypto_box_publickey($alice_kp);

$bob_kp = \Sodium\crypto_box_keypair();
$bob_secretkey = \Sodium\crypto_box_secretkey($bob_kp);
$bob_publickey = \Sodium\crypto_box_publickey($bob_kp);

$alice_to_bob_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey
  ($alice_secretkey, $bob_publickey);

$bob_to_alice_kp = \Sodium\crypto_box_keypair_from_secretkey_and_publickey
  ($bob_secretkey, $alice_publickey);

$alice_to_bob_message_nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_NONCEBYTES);

$alice_to_bob_ciphertext = \Sodium\crypto_box('Hi, this is Alice',
                                              $alice_to_bob_message_nonce,
                                              $alice_to_bob_kp);

$alice_message_decrypted_by_bob = \Sodium\crypto_box_open($alice_to_bob_ciphertext,
                                                          $alice_to_bob_message_nonce,
                                                          $bob_to_alice_kp);

$bob_to_alice_message_nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_BOX_NONCEBYTES);

$bob_to_alice_ciphertext = \Sodium\crypto_box('Hi Alice! This is Bob',
                                              $bob_to_alice_message_nonce,
                                              $bob_to_alice_kp);

$bob_message_decrypted_by_alice = \Sodium\crypto_box_open($bob_to_alice_ciphertext,
                                                          $bob_to_alice_message_nonce,
                                                          $alice_to_bob_kp);

var_dump($alice_message_decrypted_by_bob);
var_dump($bob_message_decrypted_by_alice);


if (\Sodium\library_version_major() > 7 ||
    (\Sodium\library_version_major() == 7 &&
     \Sodium\library_version_minor() >= 5)) {
    $anonymous_message_to_alice = \Sodium\crypto_box_seal('Anonymous message',
                                                          $alice_publickey);

    $decrypted_message = \Sodium\crypto_box_seal_open($anonymous_message_to_alice,
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
bool(true)
bool(true)
string(17) "Hi, this is Alice"
string(21) "Hi Alice! This is Bob"
string(17) "Anonymous message"
