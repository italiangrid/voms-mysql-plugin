
INCLUDES = -I $(top_srcdir)/mysql++-1.7.9/sqlplusint

lib_LTLIBRARIES = libvomsmysql.la
libvomsmysql_la_SOURCES = mysqlwrap.cc mysqlwrap.h dbwrap.h
libvomsmysql_la_LIBADD = $(top_builddir)/mysql++-1.7.9/sqlplusint/libmysqlplus.la $(MYSQL_LIBS)

AM_CPPFLAGS = $(MYSQL_CFLAGS)
