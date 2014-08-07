--TEST--
Check for libsodium version
--SKIPIF--
<?php if (!extension_loaded("libsodium")) print "skip"; ?>
--FILE--
<?php
echo strlen(Sodium::sodium_version_string()) >= 5;
echo "\n";
echo Sodium::sodium_library_version_major() >= 4;
echo "\n";
echo Sodium::sodium_library_version_minor() >= 0;
?>
--EXPECT--
1
1
1

