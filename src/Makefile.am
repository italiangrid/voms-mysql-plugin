
INCLUDES = -I $(top_srcdir)/mysql++-1.7.9/sqlplusint

lib_LTLIBRARIES = libvomsmysql.la
libvomsmysql_la_SOURCES = mysqlwrap.cc mysqlwrap.h dbwrap.h
libvomsmysql_la_LIBDADD = $(top_srcdir)/mysql++-1.7.9/sqlplusint/libmysqlplus.la
LIBS = -lmysqlclient

AM_CPPFLAGS = $(MYSQL_CFLAGS)