
noinst_LTLIBRARIES = librest-head.la

librest_head_la_SOURCES = \
    auth.c \
    globals.c \
    jsonbuild.c \
    jsonparse.c \
    ldapapi.c \
    libmain.c \
    operation.c \
    param.c \
    result.c

librest_head_la_CPPFLAGS = \
    -I$(top_srcdir)/include \
    -I$(top_srcdir)/include/public \
    -I$(top_srcdir)/thirdparty/openldap/include \
    -I$(top_srcdir)/thirdparty/openldap/libraries/liblber \
    -I$(top_srcdir)/thirdparty/openldap/libraries/libldap \
    -I$(top_srcdir)/server/include \
    @LW_INCLUDES@ \
    @OPENSSL_INCLUDES@ \
    @TRIDENT_INCLUDES@ \
    @JANSSON_INCLUDES@ \
    @COPENAPI_INCLUDES@

librest_head_la_LDFLAGS = \
    -static
