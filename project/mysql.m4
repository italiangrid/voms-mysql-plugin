dnl Usage:
dnl AC_MYSQL(MINIMUM-VERSION, MAXIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for mysql, and defines
dnl - MYSQL_CFLAGS (compiler flags)
dnl - MYSQL_LIBS (linker flags, stripping and path)
dnl prerequisites:


AC_DEFUN([AC_MYSQL],
[
# Get MySQL library and include locations
  AC_MSG_CHECKING([for MySQL incdir])

  AC_ARG_WITH(mysql-incdir,
	           [ --with-mysql-incdir=<dir> Default is /usr/include/mysql],
             [mysql_incdir="$withval"], 
             [mysql_incdir="/usr/include/mysql"])

  if test -d "$mysql_incdir"; then
  	AC_MSG_RESULT([found $mysql_incdir])
    MYSQL_CFLAGS="$CPPFLAGS -I$mysql_incdir"
  else
	  AC_MSG_ERROR([no such directory $mysql_incdir])
  fi  


  AC_MSG_CHECKING([for MySQL libdir])
  AC_ARG_WITH(mysql-libdir,
	            [ --with-mysql-libdir=<dir> Default is /usr/lib],
            	MYSQL_LIBS="-L$withval -lmysqlclient", 
              MYSQL_LIBS="-L/usr/lib64/mysql -L/usr/lib/mysql -lmysqlclient")


  AC_SUBST(MYSQL_CFLAGS)
  AC_SUBST(MYSQL_LIBS)
])
