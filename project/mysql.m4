dnl Usage:
dnl AC_MYSQL(MINIMUM-VERSION, MAXIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for mysql, and defines
dnl - MYSQL_CFLAGS (compiler flags)
dnl - MYSQL_LIBS (linker flags, stripping and path)
dnl prerequisites:

AC_DEFUN([mysql_version_between],
[
	l=0; for i in `echo $1 | tr . ' '`; do l=`expr $i + 1000 \* $l`; done
	m=0; for i in `echo $2 | tr . ' '`; do m=`expr $i + 1000 \* $m`; done
	r=0; for i in `echo $3 | tr . ' '`; do r=`expr $i + 1000 \* $r`; done

	if test $l -le $m -a $m -le $r; then [ $4 ]; else [ $5 ]; fi
])

AC_DEFUN([AC_MYSQL],
[
# Get MySQL library and include locations
  AC_ARG_WITH([mysql-include-path],
              [ --with-mysql-include-path   path to mysql include files],
              [MYSQL_CFLAGS="-I$withval"],
              [MYSQL_CFLAGS='-I/usr/include/mysql'])


  AC_ARG_WITH([mysql-lib-path],
              [--with-mysql-lib-path  path to mysql libraries],
              [MYSQL_LIBS="-L$withval -lmysqlclient"],
              [MYSQL_LIBS='-L /usr/lib/mysql -lmysqlclient'])

AC_SUBST([MYSQL_CFLAGS])
AC_SUBST([MYSQL_LIBS])
])
