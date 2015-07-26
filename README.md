[![Build Status](https://travis-ci.org/jedisct1/libsodium-php.png?branch=master)](https://travis-ci.org/jedisct1/libsodium-php?branch=master)

libsodium-php
=============

A simple, low-level PHP extension for
[libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 0.6.0 and PHP >= 5.4.0.

PHP 7 is also supported.

On Debian >= 8 and Ubuntu >= 15.04, libsodium can be installed with:

    apt-get install libsodium-dev
    
On OSX, libsodium can be installed with

    brew install libsodium

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
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_SECRETBOX_NONCEBYTES);
$key = [a binary string that must be \Sodium\CRYPTO_SECRETBOX_KEYBYTES long];
$ciphertext = \Sodium\crypto_secretbox('test', $nonce, $key);
$plaintext = \Sodium\crypto_secretbox_open($ciphertext, $nonce, $key);
```

The same message encrypted with the same key, but with two different
nonces, will produce two totally different ciphertexts.
Which is probably what you want.

Do not use the same `(key, nonce)` pair twice.

The nonce can be public as long as the key isn't.

`crypto_secretbox_open()` returns FALSE if the ciphertext couldn't be
verified and decrypted.

Authenticated encryption with additional data (AEAD)
----------------------------------------------------

```php
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$key = [a binary string that must be \Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES long];
$ad = 'Additional (public) data';
$ciphertext =
    \Sodium\crypto_aead_chacha20poly1305_encrypt('test', $ad, $nonce, $key);
$plaintext =
    \Sodium\crypto_aead_chacha20poly1305_decrypt($ciphertext, $ad, $nonce, $key);
```

`crypto_aead_chacha20poly1305_decrypt()` returns `FALSE` if the
ciphertext couldn't be verified and decrypted.

Public-key cryptography
=======================

Public-key signatures
---------------------

```php
$alice_kp = \Sodium\crypto_sign_keypair();
$alice_secretkey = \Sodium\crypto_sign_secretkey($alice_kp);
$alice_publickey = \Sodium\crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

// Alice signs $msg using her secret key
// $msg_signed contains the signature as well as the message
$msg_signed = \Sodium\crypto_sign($msg, $alice_secretkey);

// Bob verifies and removes the signature
$msg_orig = \Sodium\crypto_sign_open($msg_signed, $alice_publickey);
if ($msg_orig === FALSE) {
  trigger_error('Signature verification failed');
} else {
  // $msg_orig contains the original message, without the signature
}
```

`crypto_sign_open()` returns FALSE if the signature is not valid for
the given message.

The key pair can also be derived from a single seed, using
`crypto_sign_seed_keypair()`:
```php
// $seed must be \Sodium\CRYPTO_SIGN_SEEDBYTES long
$seed = \Sodium\randombytes_buf(\Sodium\CRYPTO_SIGN_SEEDBYTES);
$alice_kp = \Sodium\crypto_sign_seed_keypair($seed);
```

This operation allows Bob to check that the message has been signed by
Alice, provided that Bob knows Alice's public key.

It does *not* encrypt the message. If encryption is required in
addition to authentication, the next operation should be used instead.

Alice should never ever disclose her secret key.

Detached signatures
-------------------

```php
$alice_kp = \Sodium\crypto_sign_keypair();
$alice_secretkey = \Sodium\crypto_sign_secretkey($alice_kp);
$alice_publickey = \Sodium\crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

// Alice signs $msg using her secret key
// $signature contains only the signature
$signature = \Sodium\crypto_sign_detached($msg, $alice_secretkey);

// Bob verifies that the message signer is Alice
$verifies = \Sodium\crypto_sign_verify_detached($signature, $msg, $alice_publickey);
if ($verifies === FALSE) {
  trigger_error('Signature verification failed');
} else {
  // The signature is valid, the message is very likely to be from Alice
}
```

`crypto_sign_verify_detached()` returns FALSE if the signature is not valid for
the given message.

Public-key authenticated encryption
-----------------------------------

```php
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
```

Bob only needs Alice's public key, the nonce and the ciphertext.
Alice should never ever disclose her secret key.
Alice only needs Bob's public key, the nonce and the ciphertext.
Bob should never disclose his secret key. Unless someone drugs him and
hits him with a $5 wrench.

`crypto_box_open()` returns FALSE if the ciphertext couldn't be
verified and decrypted.

If you don't want to store public keys, the
`crypto_box_publickey_from_secretkey()` function can be used to
compute a public key given a secret key:

```php
$public_key = \Sodium\crypto_box_publickey_from_secretkey($secret_key);
```

Hash functions
==============

Generic hash function
---------------------

```php
// Fast, unkeyed hash function.
// Can be used as a secure replacement for MD5
$h = \Sodium\crypto_generichash('msg');

// Fast, keyed hash function.
// The key can be of any length between \Sodium\CRYPTO_GENERICHASH_KEYBYTES_MIN
// and \Sodium\CRYPTO_GENERICHASH_KEYBYTES_MAX, in bytes.
// \Sodium\CRYPTO_GENERICHASH_KEYBYTES is the recommended length.
$h = \Sodium\crypto_generichash('msg', $key);

// Fast, keyed hash function, with user-chosen output length, in bytes.
// Output length can be between \Sodium\CRYPTO_GENERICHASH_BYTES_MIN and
// \Sodium\CRYPTO_GENERICHASH_BYTES_MAX.
// \Sodium\CRYPTO_GENERICHASH_BYTES is the default length.
$h = \Sodium\crypto_generichash('msg', $key, 64);
```

Generic hash function (multi-part)
----------------------------------

```php
// Deterministic hash function, multi-part message
$state = \Sodium\crypto_generichash_init();
\Sodium\crypto_generichash_update($state, 'message part 1');
\Sodium\crypto_generichash_update($state, 'message part 2');
$h = \Sodium\crypto_generichash_final();

// Keyed hash function, multi-part message
$state = \Sodium\crypto_generichash_init($key);
\Sodium\crypto_generichash_update($state, 'message part 1');
\Sodium\crypto_generichash_update($state, 'message part 2');
$h = \Sodium\crypto_generichash_final();

// Keyed hash function, multi-part message with user-chosen output length
$state = \Sodium\crypto_generichash_init($key, 64);
\Sodium\crypto_generichash_update($state, 'message part 1');
\Sodium\crypto_generichash_update($state, 'message part 2');
$h = \Sodium\crypto_generichash_final(64);
```

Very fast, short (64 bits), keyed hash function
-----------------------------------------------

```php
// $key must be \Sodium\CRYPTO_SHORTHASH_KEYBYTES (16 byes, 128 bits) long
$h = \Sodium\crypto_shorthash('message', $key);
```

This function has been optimized for short messages. Its short output
length doesn't make it collision resistant.

Typical uses are:
- Building data structures such as hash tables and bloom filters.
- Adding authentication tags to network traffic.

When in doubt, use `\Sodium\crypto_generichash()` instead.

Pseudorandom numbers generators
===============================

These random number generators are cryptographically secure.

$n pseudorandom bytes
---------------------

```php
$a = \Sodium\randombytes_buf($n);
```

A pseudorandom value between 0 and 0xffff
-----------------------------------------

```php
$a = \Sodium\randombytes_random16();
```

A pseudorandom value between 0 and $n
-------------------------------------

```php
$a = \Sodium\randombytes_uniform($n);
```

Unlike `rand() % $n`, the distribution of the output values is uniform.

The maximum possible value for `$n` is `2 147 483 647`.

Stream cipher
=============

```php
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_NONCEBYTES);
$key = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_KEYBYTES);

// Derive $length pseudorandom bytes from the nonce and the key
$stream = \Sodium\crypto_stream($length, $nonce, $key);
```

Password storage
================

```php
$passwd = 'Correct battery horse staple';

// hash the password and return an ASCII string suitable for storage
$hash_str = \Sodium\crypto_pwhash_scryptsalsa208sha256_str
  ($passwd, \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// verify that the password is valid for the string that was previously stored
$valid = \Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $passwd);

// recommended: wipe the plaintext password from memory
\Sodium\memzero($passwd);

if ($valid === TRUE) {
  // password was valid
}
```

Key derivation
==============

```php
$passwd = 'Correct battery horse staple';

// create a random salt
$salt = \Sodium\randombytes_buf(\Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);

// generate a stream of $out_len pseudo random bytes
// using the password and the salt; this can be used to generate secret keys
$out_len = 100;
$key = \Sodium\crypto_pwhash_scryptsalsa208sha256
          ($out_len, $passwd, $salt,
           \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
           \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// recommended: wipe the plaintext password from memory
\Sodium\memzero($passwd);
```

Utilities
=========

Wiping sensitive information from memory
----------------------------------------

```php
$a = 'secret key';
\Sodium\memzero($a);
```

Constant-time comparison
------------------------

```php
if (\Sodium\memcmp($a, $b) === 0) {
  ...
}
```

Constant-time binary/hexadecimal conversions
--------------------------------------------

// Binary to hexadecimal
```php
$hex = \Sodium\bin2hex($bin);
```

// Hexadecimal to binary
```php
$bin = \Sodium\hex2bin($hex);
```

// Hexadecimal to binary, ignoring a set of characters
```php
$bin = \Sodium\hex2bin($hex, $string_of_characters_to_ignore);
```

Danger zone
===========

Scalar multiplication
---------------------

```php
$shared_key = \Sodium\crypto_scalarmult($alice_key, $bob_key);
```

Multiplication of the base point by a scalar is accessible as
`crypto_box_publickey_from_secretkey()`.

Unauthenticated secret-key encryption
-------------------------------------

```php
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_STREAM_NONCEBYTES);
$key = [a binary string that must be \Sodium\CRYPTO_STREAM_KEYBYTES long];
$ciphertext = \Sodium\crypto_stream_xor('test', $nonce, $key);
$plaintext = \Sodium\crypto_stream_xor($ciphertext, $nonce, $key);
```

This operation encrypts or decrypt a message with a key and a nonce.
However, the ciphertext doesn't include an authentication tag, meaning
that it is impossible to verify that the message hasn't been tampered
with.

Unless you specifically need unauthenticated encryption, `\Sodium\crypto_secretbox()`
is the operation you should use instead.

Sealed boxes
------------

```php
$alice_kp = \Sodium\crypto_box_keypair();

$anonymous_message_to_alice = \Sodium\crypto_box_seal("Anonymous message",
                                                      $alice_publickey);

$decrypted_message = \Sodium\crypto_box_seal_open($anonymous_message_to_alice,
                                                  $alice_kp);
```

Key exchange
------------

```php
$shared_key_computed_by_client = \Sodium\crypto_kx($client_secretkey, $server_publickey,
                                                   $client_publickey, $server_publickey);

$shared_key_computed_by_server = \Sodium\crypto_kx($server_secretkey, $client_publickey,
                                                   $client_publickey, $server_publickey);
```
