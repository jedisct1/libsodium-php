[![Build Status](https://travis-ci.org/jedisct1/libsodium-php.svg?branch=master)](https://travis-ci.org/jedisct1/libsodium-php?branch=master)

libsodium-php
=============

A simple, low-level PHP extension for [libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 1.0.9 and PHP >= 7.0.0.

Full documentation here:
[Using Libsodium in PHP Projects](https://paragonie.com/book/pecl-libsodium),
a guide to using the libsodium PHP extension for modern, secure, and
fast cryptography.

Installation
============

libsodium (and, if you are using binary packages, on some
distributions, `libsodium-dev` as well) have to be installed before
this extension.

Then, use the PHP extension manager:

```sh
$ sudo pecl install -f libsodium
```

On some Linux distributions such as Debian, you may have to install
PECL (`php-pear`), the PHP development package (`php-dev`) and a compiler
(`build-essential`) prior to running this command.

libsodium-php 1.x compatibility API for libsodium-php 2.x
==========================================================

For projects using the 1.x API, or willing to use it, a compatibility
layer is available.

[Polyfill Libsodium](https://github.com/mollie/polyfill-libsodium)
brings the `\Sodium\` namespace back.

Examples
========

## Encrypt a single message using a secret key

Encryption:

```php
$secret_key = sodium_crypto_secretbox_keygen();
$message = 'Sensitive information';

$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encrypted_message = sodium_crypto_secretbox($message, $nonce, $secret_key);
```

Decryption:

```php
$decrypted_message = sodium_crypto_secretbox_open($encrypted_message, $nonce, $secret_key);
```

How it works:

`$secret_key` is a secret key. Not a password. It's binary data, not
something designed to be human readable, but rather to have a key
space as large as possible for a given length.
The `keygen()` function creates such a key. That has to remain secret,
as it is used both to encrypt and decrypt data.

`$nonce` is a unique value. Like the secret, its length is fixed. But
it doesn't have to be secret, and can be sent along with the encrypted
message. The nonce doesn't have to be unpredicable either. It just has
to be unique for a given key. With the `secretbox()` API, using
`random_bytes()` is a totally fine way to generate nonces.

Encrypted messages are slightly larger than unencrypted messages,
because they include an authenticator, used by the decryption function
to check that the content was not altered.

## Encrypt a single message using a secret key, and hide its length

Encryption:

```php
$secret_key = sodium_crypto_secretbox_keygen();
$message = 'Sensitive information';
$block_size = 16;

$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$padded_message = sodium_pad($padded_message, $block_size);
$encrypted_message = sodium_crypto_secretbox($padded_message, $nonce, $secret_key);
```

Decryption:

```php
$decrypted_padded_message = sodium_crypto_secretbox_open($encrypted_message, $nonce, $secret_key);
$decrypted_message = sodium_unpad($decrypted_padded_message, $block_size);
```

How it works:

Sometimes, the length of a message may provide a lot of information
about its nature. If a message is one of "yes", "no" and "maybe",
encrypting the message doesn't help: knowing the length is enough to
know what the message is.

Padding is a technique to mitigate this, by making the length a
multiple of a given block size.

Messages must be padded prior to encryption, and unpadded after
decryption.

## Encrypt a file using a secret key

```php
$secret_key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
$input_file = '/tmp/example.original';
$encrypted_file = '/tmp/example.enc';
$chunk_size = 4096;

$fd_in = fopen($input_file, 'rb');
$fd_out = fopen($encrypted_file, 'wb');

list($stream, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($secret_key);

fwrite($fd_out, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fd_in, $chunk_size);
    if (feof($fd_in)) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }
    $encrypted_chunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fd_out, $encrypted_chunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fd_out);
fclose($fd_in);
```

Decrypt the file:

```php
$decrypted_file = '/tmp/example.dec';

$fd_in = fopen($encrypted_file, 'rb');
$fd_out = fopen($decrypted_file, 'wb');

$header = fread($fd_in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secret_key);
do {
    $chunk = fread($fd_in, $chunk_size + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    list($decrypted_chunk, $tag) = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);
    fwrite($fd_out, $decrypted_chunk);
} while (!feof($fd_in) && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
$ok = feof($fd_in);

fclose($fd_out);
fclose($fd_in);

if (!$ok) {
    die('Invalid/corrupted input');
}
```

How it works:

There's a little bit more code than in the previous examples.

In fact, `crypto_secretbox()` would work to encrypt as file, but only
if that file is pretty small. Since we have to provide the entire
content as a string, it has to fit in memory.

If the file is large, we can split it into small chunks, and encrypt
chunks individually.

By doing do, we can encrypt arbitrary large files. But we need to make
sure that chunks cannot be deleted, truncated, duplicated and
reordered. In other words, we don't have a single "message", but a
stream of messages, and during the decryption process, we need a way
to check that the whole stream matches what we encrypted.

So we create a new stream (`init_push`) and push a sequence of messages
into it (`push`). Each individual message has a tag attached to it, by
default `TAG_MESSAGE`. In order for the decryption process to know
where the end of the stream is, we tag the last message with the
`TAG_FINAL` tag.

When we consume the stream (`init_pull`, then `pull` for each
message), we check that they can be properly decrypted, and retrieve
both the decrypted chunks and the attached tags. If we read the last
chunk (`TAG_FINAL`) and we are at the end of the file, we know that we
completely recovered the original stream.

## Encrypt a file using a key derived from a password:

```php
$password = 'password';
$input_file = '/tmp/example.original';
$encrypted_file = '/tmp/example.enc';
$chunk_size = 4096;

$alg = SODIUM_CRYPTO_PWHASH_ALG_DEFAULT;
$opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
$memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

$secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                                   $password, $salt, $opslimit, $memlimit, $alg);

$fd_in = fopen($input_file, 'rb');
$fd_out = fopen($encrypted_file, 'wb');

fwrite($fd_out, pack('C', $alg));
fwrite($fd_out, pack('P', $opslimit));
fwrite($fd_out, pack('P', $memlimit));
fwrite($fd_out, $salt);

list($stream, $header) = sodium_crypto_secretstream_xchacha20poly1305_init_push($secret_key);

fwrite($fd_out, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fd_in, $chunk_size);
    if (feof($fd_in)) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }
    $encrypted_chunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fd_out, $encrypted_chunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fd_out);
fclose($fd_in);
```

Read the stored parameters and decrypt the file:

```php
$decrypted_file = '/tmp/example.dec';

$fd_in = fopen($encrypted_file, 'rb');
$fd_out = fopen($decrypted_file, 'wb');

$alg = unpack('C', fread($fd_in, 1))[1];
$opslimit = unpack('P', fread($fd_in, 8))[1];
$memlimit = unpack('P', fread($fd_in, 8))[1];
$salt = fread($fd_in, SODIUM_CRYPTO_PWHASH_SALTBYTES);

$header = fread($fd_in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$secret_key = sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
                                   $password, $salt, $opslimit, $memlimit, $alg);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secret_key);
do {
    $chunk = fread($fd_in, $chunk_size + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    $res = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);
    if ($res === FALSE) {
       break;
    }
    list($decrypted_chunk, $tag) = $res;
    fwrite($fd_out, $decrypted_chunk);
} while (!feof($fd_in) && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
$ok = feof($fd_in);

fclose($fd_out);
fclose($fd_in);

if (!$ok) {
    die('Invalid/corrupted input');
}
```

How it works:

A password cannot be directly used as a secret key. Passwords are
short, must be typable on a keyboard, and people who don't use a
password manager should be able to remember them.

A 8 characters password is thus way weaker than a 8 bytes key.

The `sodium_crypto_pwhash()` function perform a computationally
intensive operation on a password in order to derive a secret key.

By doing do, brute-forcing all possible passwords in order to find the
secret key used to encrypt the data becomes an expensive operation.

Multiple algorithms can be used to derive a key from a password, and
for each of them, different parameters can be chosen. It is important
to store all of these along with encrypted data. Using the same
algorithm and the same parameters, the same secret key can be
deterministically recomputed.

