[![Build Status](https://travis-ci.org/jedisct1/libsodium-php.svg?branch=master)](https://travis-ci.org/jedisct1/libsodium-php?branch=master)

libsodium-php
=============

A simple, low-level PHP extension for [libsodium](https://github.com/jedisct1/libsodium).

Requires libsodium >= 1.0.9 and PHP >= 7.0.0.

Full documentation here:
[Using Libsodium in PHP Projects](https://paragonie.com/book/pecl-libsodium),
a guide to using the libsodium PHP extension for modern, secure, and
fast cryptography.

libsodium-php 1.x vs libsodium-php 2.x
======================================

This extension was originally named `libsodium`. The module was named
`libsodium.so` or `libsodium.dll`).

All the related functions and constants were contained within the
`\Sodium\` namespace.

This extension was accepted to be distributed with PHP >= 7.2, albeit
with a couple breaking changes:

- No more `\Sodium\` namespace. Everything must be in the global
namespace.
- The extension should be renamed `sodium`. So, the module becomes
`sodium.so` or `sodium.dll.

The standalone extension (this repository; also the extension
available on PECL) was updated to match these expectations, so that
its API is compatible with what will be shipped with PHP 7.2.

libsodium-php 2.x is thus not compatible with libsodium-php 1.x.

The 1.x branch will not receive any public updates any more.

