--TEST--
Check for libsodium AEAD
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
$msg = \Sodium\randombytes_buf(\Sodium\randombytes_uniform(1000));
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES);
$key = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
$ad = \Sodium\randombytes_buf(\Sodium\randombytes_uniform(1000));

$ciphertext = \Sodium\crypto_aead_chacha20poly1305_encrypt($msg, $ad, $nonce, $key);
$msg2 = \Sodium\crypto_aead_chacha20poly1305_decrypt($ciphertext, $ad, $nonce, $key);
var_dump($ciphertext !== $msg);
var_dump($msg === $msg2);
var_dump(\Sodium\crypto_aead_chacha20poly1305_decrypt($ciphertext, 'x' . $ad, $nonce, $key));

$msg = \Sodium\randombytes_buf(\Sodium\randombytes_uniform(1000));
$nonce = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_AES256GCM_NPUBBYTES);
$key = \Sodium\randombytes_buf(\Sodium\CRYPTO_AEAD_AES256GCM_KEYBYTES);
$ad = \Sodium\randombytes_buf(\Sodium\randombytes_uniform(1000));

if (\Sodium\crypto_aead_aes256gcm_is_available()) {
    $ciphertext = \Sodium\crypto_aead_aes256gcm_encrypt($msg, $ad, $nonce, $key);
    $msg2 = \Sodium\crypto_aead_aes256gcm_decrypt($ciphertext, $ad, $nonce, $key);
    var_dump($ciphertext !== $msg);
    var_dump($msg === $msg2);
    var_dump(\Sodium\crypto_aead_aes256gcm_decrypt($ciphertext, 'x' . $ad, $nonce, $key));
} else {
    var_dump(true);
    var_dump(true);
    var_dump(false);    
}
?>
--EXPECT--
bool(true)
bool(true)
bool(false)
bool(true)
bool(true)
bool(false)
