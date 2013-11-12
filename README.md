libsodium-php
=============

A simple, low-level libsodium extension for PHP.

Secret-key cryptography
=======================

Secret-key authenticated encryption
-----------------------------------

```php
$nonce = randombytes_buf(CRYPTO_SECRETBOX_NONCEBYTES);
$key = randombytes_buf(CRYPTO_SECRETBOX_KEYBYTES);
$ciphertext = crypto_secretbox('test', $nonce, $key);
$plaintext = crypto_secretbox_open($ciphertext, $nonce, $key);
```

The same message encrypted with the same key, but with two different
nonces, will produce two totally different ciphertexts.
Which is usually what you want. Do not use the same `(key, nonce)`
pair twice.
The nonce can be public as long as the key isn't.

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
