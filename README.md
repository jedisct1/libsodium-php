libsodium-php
=============

A simple, low-level PHP extension for
[libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 0.5.0

Installation
============

    phpize && ./configure --with-libsodium && make test && sudo make install

And add the following line to your `php.ini` file:

    extension=libsodium.so

Secret-key cryptography
=======================

Secret-key authenticated encryption
-----------------------------------

```php
$nonce = Sodium::randombytes_buf(Sodium::CRYPTO_SECRETBOX_NONCEBYTES);
$key = [a binary string that must be CRYPTO_SECRETBOX_KEYBYTES long];
$ciphertext = Sodium::crypto_secretbox('test', $nonce, $key);
$plaintext = Sodium::crypto_secretbox_open($ciphertext, $nonce, $key);
```

The same message encrypted with the same key, but with two different
nonces, will produce two totally different ciphertexts.
Which is probably what you want.

Do not use the same `(key, nonce)` pair twice.

The nonce can be public as long as the key isn't.

Public-key cryptography
=======================

Public-key signatures
---------------------

```php
$alice_kp = Sodium::crypto_sign_keypair();
$alice_secretkey = Sodium::crypto_sign_secretkey($alice_kp);
$alice_publickey = Sodium::crypto_sign_publickey($alice_kp);

$msg = "Here is the message, to be signed using Alice's secret key, and " .
  "to be verified using Alice's public key";

// Alice signs $msg using her secret key
// $msg_signed contains the signature as well as the message
$msg_signed = Sodium::crypto_sign($msg, $alice_secretkey);

// Bob verifies and removes the signature
$msg_orig = Sodium::crypto_sign_open($msg_signed, $alice_publickey);
if ($msg_orig === FALSE) {
  trigger_error('Signature verification failed');
} else {
  // $msg_orig contains the original message, without the signature
}
```

The key pair can also be derived from a single seed, using
`crypto_sign_seed_keypair()`:
```php
// $seed must be CRYPTO_SIGN_SEEDBYTES long
$seed = Sodium::randombytes_buf(Sodium::CRYPTO_SIGN_SEEDBYTES);
$alice_kp = Sodium::crypto_sign_seed_keypair($seed);
```

This operation allows Bob to check that the message has been signed by
Alice, provided that Bob knows Alice's public key.

It does *not* encrypt the message. If encryption is required in
addition to authentication, the next operation should be used instead.

Alice should never ever disclose her secret key.

Public-key authenticated encryption
-----------------------------------

```php
$alice_kp = Sodium::crypto_box_keypair();
$alice_secretkey = Sodium::crypto_box_secretkey($alice_kp);
$alice_publickey = Sodium::crypto_box_publickey($alice_kp);

$bob_kp = Sodium::crypto_box_keypair();
$bob_secretkey = Sodium::crypto_box_secretkey($bob_kp);
$bob_publickey = Sodium::crypto_box_publickey($bob_kp);

$alice_to_bob_kp = Sodium::crypto_box_keypair_from_secretkey_and_publickey
  ($alice_secretkey, $bob_publickey);

$bob_to_alice_kp = Sodium::crypto_box_keypair_from_secretkey_and_publickey
  ($bob_secretkey, $alice_publickey);

$alice_to_bob_message_nonce = Sodium::randombytes_buf(Sodium::CRYPTO_BOX_NONCEBYTES);

$alice_to_bob_ciphertext = Sodium::crypto_box('Hi, this is Alice',
                                              $alice_to_bob_message_nonce,
                                              $alice_to_bob_kp);

$alice_message_decrypted_by_bob = Sodium::crypto_box_open($alice_to_bob_ciphertext,
                                                          $alice_to_bob_message_nonce,
                                                          $bob_to_alice_kp);

$bob_to_alice_message_nonce = Sodium::randombytes_buf(Sodium::CRYPTO_BOX_NONCEBYTES);

$bob_to_alice_ciphertext = Sodium::crypto_box('Hi Alice! This is Bob',
                                              $bob_to_alice_message_nonce,
                                              $bob_to_alice_kp);

$bob_message_decrypted_by_alice = Sodium::crypto_box_open($bob_to_alice_ciphertext,
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
$h = Sodium::crypto_generichash('msg');

// Fast, keyed hash function.
// The key can be of any length between CRYPTO_GENERICHASH_KEYBYTES_MIN
// and CRYPTO_GENERICHASH_KEYBYTES_MAX, in bytes.
// CRYPTO_GENERICHASH_KEYBYTES is the recommended length.
$h = Sodium::crypto_generichash('msg', $key);

// Fast, keyed hash function, with user-chosen output length, in bytes.
// Output length can be between CRYPTO_GENERICHASH_BYTES_MIN and
// CRYPTO_GENERICHASH_BYTES_MAX.
// CRYPTO_GENERICHASH_BYTES is the default length.
$h = Sodium::crypto_generichash('msg', $key, 64);
```

Very fast, short (64 bits), keyed hash function
-----------------------------------------------

```php
// $key must be CRYPTO_SHORTHASH_KEYBYTES (16 byes, 128 bits) long
$h = Sodium::crypto_shorthash('message', $key);
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
$a = Sodium::randombytes_buf($n);
```

A pseudorandom value between 0 and 0xffff
-----------------------------------------

```php
$a = Sodium::randombytes_random16();
```

A pseudorandom value between 0 and $n
-------------------------------------

```php
$a = Sodium::randombytes_uniform($n);
```

Unlike `rand() % $n`, the distribution of the output values is uniform.

Password storage
================

```php
$passwd = 'Correct battery horse staple';

// hash the password and return an ASCII string suitable for storage
$hash_str = Sodium::crypto_pwhash_scryptsalsa208sha256_str
  ($passwd, Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// verify that the password is valid for the string that was previously stored
$valid = Sodium::crypto_pwhash_scryptsalsa208sha256_str_verify($hash_str, $passwd);

// recommended: wipe the plaintext password from memory
Sodium::sodium_memzero($passwd);

if ($valid === TRUE) {
  // password was valid
}
```

Key derivation
==============

```php
$passwd = 'Correct battery horse staple';

// create a random salt
$salt = Sodium::randombytes_buf(Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES);

// generate a stream of $out_len pseudo random bytes
// using the password and the salt; this can be used to generate secret keys
$out_len = 100;
$key = Sodium::crypto_pwhash_scryptsalsa208sha256
          ($out_len, $passwd, $salt,
           Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
           Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE);

// recommended: wipe the plaintext password from memory
Sodium::sodium_memzero($passwd);
```


Utilities
=========

Wiping sensitive information from memory
----------------------------------------

```php
$a = 'secret key';
Sodium::sodium_memzero($a);
```

Constant-time comparison
------------------------

```php
if (Sodium::sodium_memcmp($a, $b) === 0) {
  ...
}
```
