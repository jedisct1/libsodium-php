dnl $Id$
dnl config.m4 for extension libsodium

PHP_ARG_WITH(libsodium, for libsodium support,
[  --with-libsodium[[=DIR]]  Include libsodium support])

if test "$PHP_LIBSODIUM" != "no"; then
  SEARCH_PATH="/usr/local /usr"     # you might want to change this
  SEARCH_FOR="/include/sodium.h"  # you most likely want to change this
  if test -r $PHP_LIBSODIUM/$SEARCH_FOR; then # path given as parameter
    LIBSODIUM_DIR=$PHP_LIBSODIUM
  else # search default path list
    AC_MSG_CHECKING([for libsodium files in default path])
    for i in $SEARCH_PATH ; do
      if test -r $i/$SEARCH_FOR; then
        LIBSODIUM_DIR=$i
        AC_MSG_RESULT(found in $i)
      fi
    done
  fi

  if test -z "$LIBSODIUM_DIR"; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR([Please install libsodium - See https://github.com/jedisct1/libsodium])
  fi

  PHP_ADD_INCLUDE($LIBSODIUM_DIR/include)

  LIBNAME=sodium
  LIBSYMBOL=crypto_pwhash_scryptsalsa208sha256

  PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  [
    PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LIBSODIUM_DIR/$PHP_LIBDIR, LIBSODIUM_SHARED_LIBADD)
    AC_DEFINE(HAVE_LIBSODIUMLIB,1,[ ])
  ],[
    AC_MSG_ERROR([wrong libsodium lib version or lib not found])
  ],[
    -L$LIBSODIUM_DIR/$PHP_LIBDIR
  ])
  PHP_CHECK_LIBRARY($LIBNAME,crypto_aead_aes256gcm_encrypt,
  [
    AC_DEFINE(HAVE_CRYPTO_AEAD_AES256GCM,1,[ ])
  ],[],[
    -L$LIBSODIUM_DIR/$PHP_LIBDIR
  ])

  PHP_SUBST(LIBSODIUM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(libsodium, libsodium.c, $ext_shared)
fi
