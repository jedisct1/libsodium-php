[![Build Status](https://travis-ci.org/jedisct1/libsodium-php.svg?branch=master)](https://travis-ci.org/jedisct1/libsodium-php?branch=master)

libsodium-php
=============

A simple, low-level PHP extension for [libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 1.0.9 and PHP 7.{0,1,2,3,4}.x

Full documentation here:
[Using Libsodium in PHP Projects](https://paragonie.com/book/pecl-libsodium),
a guide to using the libsodium PHP extension for modern, secure, and
fast cryptography.

Installation
============

libsodium (and, if you are using binary packages, on some
distributions, `libsodium-dev` as well) has to be installed before
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
$secretKey = sodium_crypto_secretbox_keygen();
$message = 'Sensitive information';

$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$encryptedMessage = sodium_crypto_secretbox($message, $nonce, $secretKey);
```

Decryption:

```php
$decryptedMessage = sodium_crypto_secretbox_open($encryptedMessage, $nonce, $secretKey);
```

How it works:

`$secret_key` is a secret key. Not a password. It's binary data, not
something designed to be human readable, but rather to have a key
space as large as possible for a given length.
The `keygen()` function creates such a key. That has to remain secret,
as it is used both to encrypt and decrypt data.

`$nonce` is a unique value. Like the secret, its length is fixed. But
it doesn't have to be secret, and can be sent along with the encrypted
message. The nonce doesn't have to be unpredictable either. It just has
to be unique for a given key. With the `secretbox()` API, using
`random_bytes()` is a totally fine way to generate nonces.

Encrypted messages are slightly larger than unencrypted messages,
because they include an authenticator, used by the decryption function
to check that the content was not altered.

## Encrypt a single message using a secret key, and hide its length

Encryption:

```php
$secretKey = sodium_crypto_secretbox_keygen();
$message = 'Sensitive information';
$blockSize = 16;

$nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
$paddedMessage = sodium_pad($message, $blockSize);
$encryptedMessage = sodium_crypto_secretbox($paddedMessage, $nonce, $secretKey);
```

Decryption:

```php
$decryptedPaddedMessage = sodium_crypto_secretbox_open($encryptedMessage, $nonce, $secretKey);
$decryptedMessage = sodium_unpad($decryptedPaddedMessage, $blockSize);
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
$secretKey = sodium_crypto_secretstream_xchacha20poly1305_keygen();
$inputFile = '/tmp/example.original';
$encryptedFile = '/tmp/example.enc';
$chunkSize = 4096;

$fdIn = fopen($inputFile, 'rb');
$fdOut = fopen($encryptedFile, 'wb');

[$stream, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($secretKey);

fwrite($fdOut, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fdIn, $chunkSize);

    if (feof($fdIn)) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }

    $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fdOut, $encryptedChunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fdOut);
fclose($fdIn);
```

Decrypt the file:

```php
$decryptedFile = '/tmp/example.dec';

$fdIn = fopen($encryptedFile, 'rb');
$fdOut = fopen($decryptedFile, 'wb');

$header = fread($fdIn, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secretKey);
do {
    $chunk = fread($fdIn, $chunkSize + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    [$decryptedChunk, $tag] = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);

    fwrite($fdOut, $decryptedChunk);
} while (!feof($fdIn) && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
$ok = feof($fdIn);

fclose($fdOut);
fclose($fdIn);

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
$inputFile = '/tmp/example.original';
$encryptedFile = '/tmp/example.enc';
$chunkSize = 4096;

$alg = SODIUM_CRYPTO_PWHASH_ALG_DEFAULT;
$opsLimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
$memLimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;
$salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);

$secretKey = sodium_crypto_pwhash(
    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    $password,
    $salt,
    $opsLimit,
    $memLimit,
    $alg
);

$fdIn = fopen($inputFile, 'rb');
$fdOut = fopen($encryptedFile, 'wb');

fwrite($fdOut, pack('C', $alg));
fwrite($fdOut, pack('P', $opsLimit));
fwrite($fdOut, pack('P', $memLimit));
fwrite($fdOut, $salt);

[$stream, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($secretKey);

fwrite($fdOut, $header);

$tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
do {
    $chunk = fread($fdIn, $chunkSize);
    if (feof($fdIn)) {
        $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }

    $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push($stream, $chunk, '', $tag);
    fwrite($fdOut, $encryptedChunk);
} while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);

fclose($fdOut);
fclose($fdIn);
```

Read the stored parameters and decrypt the file:

```php
$decryptedFile = '/tmp/example.dec';

$fdIn = fopen($encryptedFile, 'rb');
$fdOut = fopen($decryptedFile, 'wb');

$alg = unpack('C', fread($fdIn, 1))[1];
$opsLimit = unpack('P', fread($fdIn, 8))[1];
$memLimit = unpack('P', fread($fdIn, 8))[1];
$salt = fread($fdIn, SODIUM_CRYPTO_PWHASH_SALTBYTES);

$header = fread($fdIn, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

$secretKey = sodium_crypto_pwhash(
    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
    $password,
    $salt,
    $opsLimit,
    $memLimit,
    $alg
);

$stream = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $secretKey);
do {
    $chunk = fread($fdIn, $chunkSize + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
    $res = sodium_crypto_secretstream_xchacha20poly1305_pull($stream, $chunk);

    if ($res === false) {
        break;
    }
    
    [$decrypted_chunk, $tag] = $res;
    fwrite($fdOut, $decrypted_chunk);
} while (!feof($fdIn) && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
$ok = feof($fdIn);

fclose($fdOut);
fclose($fdIn);

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
