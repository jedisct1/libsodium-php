
#ifndef COMPAT_H
#define COMPAT_H

#if PHP_MAJOR_VERSION >= 7

typedef size_t strsize_t;

# define STRSIZE_MAX ZEND_SIZE_MAX
# define ZSTR_TRUNCATE(zs, len) do { ZSTR_LEN(zs) = (len); } while(0)

#else

typedef char zend_string;
typedef int  strsize_t;
typedef long zend_long;

# define ZVAL_DEREF(zv) (void) (zv)

# define ZEND_SIZE_MAX INT_MAX
# define STRSIZE_MAX INT_MAX

# undef  RETURN_STRING
# define RETURN_STRING(s) \
    do { \
        RETVAL_STRING((s), 1); \
        return; \
    } while(0)

# define RETURN_STR(zs_) \
    do { \
        zend_string *zs = zs_; \
        RETVAL_STRINGL(ZSTR_VAL(zs), ZSTR_LEN(zs), 0); \
        return; \
    } while(0)

static zend_always_inline strsize_t
ZSTR_LEN(const zend_string *zs)
{
    strsize_t len;

    memcpy(&len, zs + sizeof (char *), sizeof len);
    return len;
}

static zend_always_inline char *
ZSTR_VAL(const zend_string *zs)
{
    char *zsx;

    memcpy(&zsx, zs, sizeof zsx);
    return zsx;
}

static void
ZSTR_TRUNCATE(zend_string *zs, strsize_t new_len)
{
    if (new_len >= (strsize_t) (zs - ZSTR_VAL(zs))) {
        zend_error_noreturn(E_ERROR,
                            "ZSTR_TRUNCATE() truncating beyond maximum buffer size");
    }
    memcpy(zs + sizeof (char *), &new_len, sizeof new_len);
}

static zend_string *
zend_string_alloc(strsize_t len, int persistent)
{
    char        *zsx;
    zend_string *zs;

    if (persistent != 0) {
        zend_error_noreturn(E_ERROR,
                            "zend_string_alloc() called with persistency");
    }
    if (ZEND_SIZE_MAX - 1U - (sizeof zsx) - (sizeof len) <= len) {
        zend_error_noreturn(E_ERROR,
                            "Possible integer overflow in memory allocation");
    }
    zsx = safe_emalloc(len + 1U + (sizeof zsx) + (sizeof len), 1U, 0U);
    memset(zsx, 0, (size_t) len + (size_t) 1U);
    zs = zsx + len + 1U;
    memcpy(zs, &zsx, sizeof zsx);
    memcpy(zs + sizeof zsx, &len, sizeof len);

    return zs;
}

static void
zend_string_free(zend_string *zs)
{
    char *zsx;

    if (zs == NULL) {
        return;
    }
    memcpy(&zsx, zs, sizeof zsx);
    memset(zsx, 0, ZSTR_LEN(zs) + 1U + (sizeof zsx) + sizeof (strsize_t));
    efree(zsx);
}

#endif

#endif
