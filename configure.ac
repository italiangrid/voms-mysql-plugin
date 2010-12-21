
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([Glite Security VOMS MySQL], [3.1.5])

command_line="$@"

AC_CONFIG_AUX_DIR([./project])
AM_INIT_AUTOMAKE([1.6.3 subdir-objects])
AC_CONFIG_SRCDIR([src/dbwrap.h])

AM_MAINTAINER_MODE

AC_ARG_WITH([rpm-dir],
            [  --with-rpm-dir=DIR      rpm topdir in DIR [`pwd`]],
            [rpm_topdir=$withval],[rpm_topdir=`pwd`])

if test -d $rpm_topdir ; then
    AC_MSG_RESULT([$rpm_topdir found])
    else
     AC_MSG_RESULT([$rpm_topdir not found])
fi
RPM_TOPDIR=$rpm_topdir
AC_SUBST(RPM_TOPDIR)

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

if test "x$prefix" = xNONE; then
   mypref=$ac_default_prefix
else
   mypref=$prefix
fi
AC_DEFINE_UNQUOTED(PROGPREFIX, "${mypref}", PROGPREFIX)
PPREFIX=${mypref}
AC_SUBST(PPREFIX)

AC_MSG_CHECKING([for command line])
COMMAND_LINE=""
for i in $command_line; do
if test $i != "--no-create" ; then
   COMMAND_LINE="$COMMAND_LINE $i"
fi
done
AC_MSG_RESULT([found $COMMAND_LINE])
AC_SUBST(COMMAND_LINE)

# Dependencies checks
have_mysql=no
AC_MYSQL([4.0.11], [9.9.99], have_mysql=yes, have_mysql=no)
AC_MSG_RESULT(["MySQL found $have_mysql"])

AC_GLITE

AM_CONFIG_HEADER([src/autogen/config.h])
AC_CONFIG_FILES([Makefile
                 config/Makefile
                 src/Makefile
                 glite-security-voms-mysql.spec])

AC_OUTPUT
