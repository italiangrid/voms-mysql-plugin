/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003, 2004, 2005 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#include "dbwrap.h"

#include <string>

extern "C" {
#include <mysql.h>
#include <mysqld_error.h>
}

namespace bsq {

class myinterface;
class myquery;

class myresults : public sqliface::results 
{

public:
  
  friend class myquery;

  ~myresults();

  int size() const;

  const std::string get(int) const;
  const std::string get(const std::string&) const;

  bool next();

  bool valid() const;

  const std::string name(int i) const;

private:

  myresults(MYSQL_RES * res);
  //myresults(MYSQL * mysql);
  myresults();
  myresults(const myresults& other);

  MYSQL_RES * result;
  MYSQL_ROW row;
  bool value;

};

class myquery : public sqliface::query 
{

public:
 
  friend class myinterface;
  
  myquery(const myquery& other);
  ~myquery();
  
  sqliface::query &operator<<(std::string);

  sqliface::results *result(void);
  void exec(void);
  
  int  error(void) const;
  
private:

  myquery();
  myquery(myinterface&);

  std::string query_text;
  MYSQL * mysql;
  int err;

};

class myinterface : public sqliface::interface 
{

  friend class myquery;

public:

  myinterface();

  myinterface(const char * dbname,
              const char * hostname,
              const char * user,
              const char * password);

  ~myinterface(void);

  void connect(const char * dbname, 
               const char * hostname, 
               const char * user, 
               const char * password);
  
  int error(void) const;

  sqliface::query * newquery();

 private:

  myinterface(const myinterface &);
  
  MYSQL * mysql;
  int err;
  
};

};

extern sqliface::interface *CreateDB();
