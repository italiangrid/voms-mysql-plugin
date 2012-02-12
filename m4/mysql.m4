dnl Usage:
dnl Test for mysql, and defines
dnl - MYSQL_CFLAGS (compiler flags)
dnl - MYSQL_LIBS (linker flags, stripping and path)
dnl prerequisites:

AC_DEFUN([AC_MYSQL],
[
	# Get MySQL library and include locations
	AC_MSG_CHECKING([MySQL include path])

	AC_ARG_WITH(mysql-incdir,
		[  --with-mysql-incdir=DIR Default is /usr/include/mysql],
		[mysql_incdir="$withval"], 
		[mysql_incdir="/usr/include/mysql"]
	)

	
	if test -d "$mysql_incdir"; then
		AC_MSG_RESULT([found $mysql_incdir])
		MYSQL_CFLAGS="$CPPFLAGS -I$mysql_incdir"
	else
		AC_MSG_ERROR([no such directory $mysql_incdir])
	fi  

	AC_MSG_CHECKING([MySQL library path])
	AC_ARG_WITH(mysql-libdir,
		[  --with-mysql-libdir=DIR Default is /usr/lib],
		MYSQL_LIBS="-L$withval -lmysqlclient", 
		MYSQL_LIBS="-L/usr/lib64/mysql -L/usr/lib/mysql -lmysqlclient"
	)

	AC_SUBST(MYSQL_CFLAGS)
	AC_SUBST(MYSQL_LIBS)
])
