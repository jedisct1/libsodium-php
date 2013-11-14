libsodium-php
=============

A simple, low-level PHP extension for
[libsodium](https://github.com/jedisct1/libsodium).

Secret-key cryptography
=======================

Secret-key authenticated encryption
-----------------------------------

```php
$nonce = randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES);
$key = [a binary string that should be CRYPTO_SECRETBOX_KEYBYTES long];
$ciphertext = crypto_secretbox('test', $nonce, $key);
$plaintext = crypto_secretbox_open($ciphertext, $nonce, $key);
```

The same message encrypted with the same key, but with two different
nonces, will produce two totally different ciphertexts.
Which is probably what you want.

Do not use the same `(key, nonce)` pair twice.

The nonce can be public as long as the key isn't.

Public-key authenticated encryption
-----------------------------------

```php
$alice_kp = crypto_box_keypair();
$alice_secretkey = crypto_box_secretkey($alice_kp);
$alice_publickey = crypto_box_publickey($alice_kp);

$bob_kp = crypto_box_keypair();
$bob_secretkey = crypto_box_secretkey($bob_kp);
$bob_publickey = crypto_box_publickey($bob_kp);

$alice_to_bob_kp = crypto_box_keypair_from_secretkey_and_publickey
  ($alice_secretkey, $bob_publickey);

$bob_to_alice_kp = crypto_box_keypair_from_secretkey_and_publickey
  ($bob_secretkey, $alice_publickey);

$alice_to_bob_message_nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES);

$alice_to_bob_ciphertext = crypto_box('Hi, this is Alice',
                                      $alice_to_bob_message_nonce,
                                      $alice_to_bob_kp);

$alice_message_decrypted_by_bob = crypto_box_open($alice_to_bob_ciphertext,
                                                  $alice_to_bob_message_nonce,
                                                  $bob_to_alice_kp);

$bob_to_alice_message_nonce = randombytes_buf(CRYPTO_BOX_NONCEBYTES);

$bob_to_alice_ciphertext = crypto_box('Hi Alice! This is Bob',
                                      $bob_to_alice_message_nonce,
                                      $bob_to_alice_kp);

$bob_message_decrypted_by_alice = crypto_box_open($bob_to_alice_ciphertext,
                                                  $bob_to_alice_message_nonce,
                                                  $alice_to_bob_kp);
```

Bob only needs Alice's public key, the nonce and the ciphertext.
Alice should never disclose her secret key.
Alice only needs Bob's public key, the nonce and the ciphertext.
Bob should never disclose his secret key. Unless someone drugs him and
hits him with a $5 wrench.

If you want don't want to store public keys, the
`crypto_box_publickey_from_secretkey()` function can be used to
compute a public key given a secret key.

Hash functions
==============

Generic hash function
---------------------

```php
// Fast, unkeyed hash function.
// Can be used as a secure remplacement for MD5
$h = crypto_generichash('msg');

// Fast, keyed hash function.
// The key can be of any length between CRYPTO_GENERICHASH_KEYBYTES_MIN
// and CRYPTO_GENERICHASH_KEYBYTES_MAX, in bytes.
// CRYPTO_GENERICHASH_KEYBYTES is the recommended length.
$h = crypto_generichash('msg', $key);

// Fast, keyed hash function, with user-chosen output length, in bytes.
// Output length can be between CRYPTO_GENERICHASH_BYTES_MIN and
// CRYPTO_GENERICHASH_BYTES_MAX.
// CRYPTO_GENERICHASH_BYTES is the default length.
$h = crypto_generichash('msg', $key, 64);
```

Very Fast, short (64 bits), keyed hash function
-----------------------------------------------

```php
// $key must be 16 bytes (128 bits) long
$h = crypto_shorthash('message', $key);
```

This function has been optimized for short messages. Its short output
length doesn't make it collision resistant.

Typical uses are:
- Building data structures such as hash tables and bloom filters.
- Adding authentication tags to network traffic.

When in doubt, use `crypto_generichash()` instead.

Pseudorandom numbers generators
===============================

These random number generators are cryptographically secure.

$n pseudorandom bytes
---------------------

```php
$a = randombytes_buf($n);
```

A pseudorandom 32-bit value
---------------------------

```php
$a = randombyes_random();
```

A pseudorandom value between 0 and $n
-------------------------------------

```php
$a = randombytes_uniform($n);
```

Unlike `rand() % $n`, the distribution of the output values is uniform.

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
