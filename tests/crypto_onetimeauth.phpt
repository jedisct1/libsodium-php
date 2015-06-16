--TEST--
Check for libsodium onetimeauth
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$key = str_repeat(chr(96), Sodium::CRYPTO_ONETIMEAUTH_KEYBYTES);
$q = Sodium::crypto_onetimeauth('msg', $key);
var_dump(bin2hex($q));

$randomBytes = Sodium::randombytes_buf(128);
$randomKey = Sodium::randombytes_buf(Sodium::CRYPTO_ONETIMEAUTH_KEYBYTES);

$normalAuth = Sodium::crypto_onetimeauth($randomBytes, $randomKey);

$partialState = Sodium::crypto_onetimeauth_init($randomKey);
for ($i = 0; $i < 8; $i++) {
	Sodium::crypto_onetimeauth_update($partialState, substr($randomBytes, $i * 16, 16));
}
$authByParts = Sodium::crypto_onetimeauth_final($partialState);
var_dump($normalAuth === $authByParts);

?>
--EXPECT--
string(32) "643255fb921055fb921055fb921055fb"
bool(true)
