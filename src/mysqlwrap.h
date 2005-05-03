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
#include <iterator>
#include <string>
#include <list>

#include <sqlplus.hh>

#include "dbwrap.h"

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

  myresults(Query *);
  myresults();
  myresults(myresults const &);

  Row row;
  ResUse res;
  bool value;

};

class myquery : public sqliface::query 
{

public:

  friend class myiterator;
  friend class myinterface;
  
  myquery(const myquery &);
  ~myquery();
  
  sqliface::query &operator<<(std::string);

  // query execution

  sqliface::results *result(void);
  void exec(void);
  
  int  error(void) const;

private:

  myquery();
  myquery(myinterface&);
  std::string query_text;
  Connection *c;
  Query q;

};

class myinterface : public sqliface::interface 
{

  friend class myquery;

public:

  myinterface();
  myinterface(const char *, const char *, const char *, const char *);
  ~myinterface(void);
  int error(void) const;
  void connect(const char *, const char *, const char *, const char *);
  sqliface::query *newquery();

private:

  myinterface(const myinterface &);
  Connection con;
  int err;

};

};

extern sqliface::interface *CreateDB();
