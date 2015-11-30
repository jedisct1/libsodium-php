--TEST--
Check for libsodium auth
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$msg = \Sodium\randombytes_buf(1000);
$key = \Sodium\randombytes_buf(\Sodium\CRYPTO_AUTH_KEYBYTES);
$mac = \Sodium\crypto_auth($msg, $key);

// This should validate
var_dump(\Sodium\crypto_auth_verify($mac, $msg, $key));

// Flip the first bit
$badmsg = $msg;
$badmsg[0] = \chr(\ord($badmsg[0]) ^ 0x80);
var_dump(\Sodium\crypto_auth_verify($mac, $badmsg, $key));

// Let's flip a bit pseudo-randomly
$badmsg = $msg;
$badmsg[$i=mt_rand(0, 999)] = \chr(
    \ord($msg[$i]) ^ (
        1 << mt_rand(0, 7)
    )
);

var_dump(\Sodium\crypto_auth_verify($mac, $badmsg, $key));

// Now let's change a bit in the MAC
$badmac = $mac;
$badmac[0] = \chr(\ord($badmac[0]) ^ 0x80);
var_dump(\Sodium\crypto_auth_verify($badmac, $msg, $key));
?>
--EXPECT--
bool(true)
bool(false)
bool(false)
bool(false)
