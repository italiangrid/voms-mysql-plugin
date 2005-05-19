
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([Glite Security VOMS MySQL], [1.0.0])
AC_CONFIG_AUX_DIR([./project])
AM_INIT_AUTOMAKE([1.6.3 subdir-objects])
AC_CONFIG_SRCDIR([src/dbwrap.h])

#Environment.
WORKDIR=`pwd`
AC_SUBST(WORKDIR)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_CXXCPP
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([mysqlclient], [main])

SQLPLUSVERSION=1.7.0
SQLPLUS_MAJOR_VERSION=[`expr $SQLPLUSVERSION : '\([0-9][0-9]*\)'`]
AC_SUBST(SQLPLUS_MAJOR_VERSION)
SQLPLUS_MINOR_VERSION=[`expr $SQLPLUSVERSION : '[0-9][0-9]*\.\([0-9][0-9]*\)'`]
AC_SUBST(SQLPLUS_MINOR_VERSION)
SQLPLUS_MICRO_VERSION=[`expr $SQLPLUSVERSION : '[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\)'`]
AC_SUBST(SQLPLUS_MICRO_VERSION)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_STAT
AC_FUNC_STRTOD
AC_CHECK_FUNCS([strtol strtoul strtoull])

# Dependencies checks
have_mysql=no
AC_MYSQL([4.0.11], [4.1.11], have_mysql=yes, have_mysql=no)
AC_MSG_RESULT(["MySQL found $have_mysql"])

AC_GLITE

AM_CONFIG_HEADER([src/autogen/config.h])
AC_CONFIG_FILES([Makefile
		 config/Makefile
                 mysql++-1.7.9/Makefile
                 mysql++-1.7.9/sqlplusint/Makefile
                 src/Makefile])

AC_OUTPUT
