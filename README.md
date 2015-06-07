[![Build Status](https://travis-ci.org/jedisct1/libsodium-php.png?branch=master)](https://travis-ci.org/jedisct1/libsodium-php?branch=master)

libsodium-php
=============

A simple, low-level PHP extension for
[libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 0.6.0 and PHP >= 5.4.0

On Debian 8 and Ubuntu 15.04, libsodium can be installed with:

    apt-get install libsodium-dev

Installation
============

    pecl install libsodium-beta

And add the following line to your `php.ini` file:

    extension=libsodium.so

Secret-key cryptography
=======================

Secret-key authenticated encryption
-----------------------------------

```php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$key = [a binary string that must be SODIUM_CRYPTO_SECRETBOX_KEYBYTES long];
$ciphertext = sodium_crypto_secretbox('test', $nonce, $key);
$plaintext = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
```

The same message encrypted with the same key, but with two different
nonces, will produce two totally different ciphertexts.
Which is probably what you want.

Do not use the same `(key, nonce)` pair twice.

The nonce can be public as long as the key isn't.

Authenticated encryption with additional data (AEAD)
----------------------------------------------------

```php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$key = [a binary string that must be SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long];
$ad = 'Additional (public) data';
$ciphertext =
    sodium_crypto_aead_chacha20poly1305_encrypt('test', $ad, $nonce, $key);
$plaintext =
    sodium_crypto_aead_chacha20poly1305_decrypt($ciphertext, $ad, $nonce, $key);
```

Public-key cryptography
=======================

Public-key signatures
---------------------

```php
$alice_kp = sodium_crypto_sign_keypair();
$alice_secretkey = sodium_crypto_sign_secretkey($alice_kp);
$alice_publickey = sodium_crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

// Alice signs $msg using her secret key
// $msg_signed contains the signature as well as the message
$msg_signed = sodium_crypto_sign($msg, $alice_secretkey);

// Bob verifies and removes the signature
$msg_orig = sodium_crypto_sign_open($msg_signed, $alice_publickey);
if ($msg_orig === FALSE) {
  trigger_error('Signature verification failed');
} else {
  // $msg_orig contains the original message, without the signature
}
```

The key pair can also be derived from a single seed, using
`crypto_sign_seed_keypair()`:
```php
// $seed must be SODIUM_CRYPTO_SIGN_SEEDBYTES long
$seed = sodium_randombytes_buf(SODIUM_CRYPTO_SIGN_SEEDBYTES);
$alice_kp = sodium_crypto_sign_seed_keypair($seed);
```

This operation allows Bob to check that the message has been signed by
Alice, provided that Bob knows Alice's public key.

It does *not* encrypt the message. If encryption is required in
addition to authentication, the next operation should be used instead.

Alice should never ever disclose her secret key.

Detached signatures
-------------------

```php
$alice_kp = sodium_crypto_sign_keypair();
$alice_secretkey = sodium_crypto_sign_secretkey($alice_kp);
$alice_publickey = sodium_crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

// Alice signs $msg using her secret key
// $signature contains only the signature
$signature = sodium_crypto_sign_detached($msg, $alice_secretkey);

// Bob verifies that the message signer is Alice
$verifies = sodium_crypto_sign_verify_detached($signature, $msg, $alice_publickey);
if ($verifies === FALSE) {
  trigger_error('Signature verification failed');
} else {
  // The signature is valid, the message is very likely to be from Alice
}
```

Public-key authenticated encryption
-----------------------------------

```php
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
```

Bob only needs Alice's public key, the nonce and the ciphertext.
Alice should never ever disclose her secret key.
Alice only needs Bob's public key, the nonce and the ciphertext.
Bob should never disclose his secret key. Unless someone drugs him and
hits him with a $5 wrench.

If you don't want to store public keys, the
`crypto_box_publickey_from_secretkey()` function can be used to
compute a public key given a secret key.

Hash functions
==============

Generic hash function
---------------------

```php
// Fast, unkeyed hash function.
// Can be used as a secure remplacement for MD5
$h = sodium_crypto_generichash('msg');

// Fast, keyed hash function.
// The key can be of any length between SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN
// and SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX, in bytes.
// SODIUM_CRYPTO_GENERICHASH_KEYBYTES is the recommended length.
$h = sodium_crypto_generichash('msg', $key);

// Fast, keyed hash function, with user-chosen output length, in bytes.
// Output length can be between SODIUM_CRYPTO_GENERICHASH_BYTES_MIN and
// SODIUM_CRYPTO_GENERICHASH_BYTES_MAX.
// SODIUM_CRYPTO_GENERICHASH_BYTES is the default length.
$h = sodium_crypto_generichash('msg', $key, 64);
```

Very fast, short (64 bits), keyed hash function
-----------------------------------------------

```php
// $key must be SODIUM_CRYPTO_SHORTHASH_KEYBYTES (16 byes, 128 bits) long
$h = sodium_crypto_shorthash('message', $key);
```

This function has been optimized for short messages. Its short output
length doesn't make it collision resistant.

Typical uses are:
- Building data structures such as hash tables and bloom filters.
- Adding authentication tags to network traffic.

When in doubt, use `sodium_crypto_generichash()` instead.

Pseudorandom numbers generators
===============================

These random number generators are cryptographically secure.

$n pseudorandom bytes
---------------------

```php
$a = sodium_randombytes_buf($n);
```

A pseudorandom value between 0 and 0xffff
-----------------------------------------

```php
$a = sodium_randombytes_random16();
```

A pseudorandom value between 0 and $n
-------------------------------------

```php
$a = sodium_randombytes_uniform($n);
```

Unlike `rand() % $n`, the distribution of the output values is uniform.

The maximum possible value for `$n` is `2 147 483 647`.

Stream cipher
=============

``` php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_NONCEBYTES);
$key = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_KEYBYTES);

// Derive $length pseudorandom bytes from the nonce and the key
$stream = sodium_crypto_stream($length, $nonce, $key);
```

Password storage
================

```php
$passwd = 'Correct battery horse staple';

// hash the password and return an ASCII string suitable for storage
$hash_str = sodium_crypto_pwhash_scryptsalsa208sha256_str
  ($passwd, SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// verify that the password is valid for the string that was previously stored
$valid = sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $passwd);

// recommended: wipe the plaintext password from memory
sodium_memzero($passwd);

if ($valid === TRUE) {
  // password was valid
}
```

Key derivation
==============

```php
$passwd = 'Correct battery horse staple';

// create a random salt
$salt = sodium_randombytes_buf(SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);

// generate a stream of $out_len pseudo random bytes
// using the password and the salt; this can be used to generate secret keys
$out_len = 100;
$key = sodium_crypto_pwhash_scryptsalsa208sha256
          ($out_len, $passwd, $salt,
           SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
           SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// recommended: wipe the plaintext password from memory
sodium_memzero($passwd);
```

Utilities
=========

Wiping sensitive information from memory
----------------------------------------

```php
$a = 'secret key';
sodium_memzero($a);
```

Constant-time comparison
------------------------

```php
if (sodium_memcmp($a, $b) === 0) {
  ...
}
```

Constant-time binary/hexadecimal conversions
--------------------------------------------

// Binary to hexadecimal
```php
$hex = sodium_bin2hex($bin);
```

// Hexadecimal to binary
```php
$bin = sodium_hex2bin($hex);
```

// Hexadecimal to binary, ignoring a set of characters
```php
$bin = sodium_hex2bin($hex, $string_of_characters_to_ignore);
```

Danger zone
===========

Scalar multiplication
---------------------

```php
$shared_key = sodium_crypto_scalarmult($alice_key, $bob_key);
```

Unauthenticated secret-key encryption
-------------------------------------

```php
$nonce = sodium_randombytes_buf(SODIUM_CRYPTO_STREAM_NONCEBYTES);
$key = [a binary string that must be SODIUM_CRYPTO_STREAM_KEYBYTES long];
$ciphertext = sodium_crypto_stream_xor('test', $nonce, $key);
$plaintext = sodium_crypto_stream_xor($ciphertext, $nonce, $key);
```

This operation encrypts or decrypt a message with a key and a nonce.
However, the ciphertext doesn't include an authentication tag, meaning
that it is impossible to verify that the message hasn't been tampered
with.

Unless you specifically need unauthenticated encryption, `sodium_crypto_secretbox()`
is the operation you should use instead.

Sealed boxes
------------

```php
$alice_kp = sodium_crypto_box_keypair();

$anonymous_message_to_alice = sodium_crypto_box_seal("Anonymous message",
                                                      $alice_publickey);

$decrypted_message = sodium_crypto_box_seal_open($anonymous_message_to_alice,
                                                  $alice_kp);
```
