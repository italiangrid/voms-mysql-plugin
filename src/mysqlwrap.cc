/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *          Valerio Venturi - valerio.venturi@cnaf.infn.it
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#include "mysqlwrap.h"

#include <string>
#include <algorithm>
#include <cctype>

namespace bsq {

static bool nocase_compare(char c1, char c2)
{
  return (toupper(c1) == toupper(c2));
}

myinterface::myinterface() : mysql(mysql_init(0)),
                             err(0) 
{
  if (!mysql) {
    throw sqliface::DBEXC(mysql_error(mysql));
  }
}
  
myinterface::myinterface(const char * dbname, 
                         const char * hostname,
                         const char * user,
                         const char * password) : mysql(mysql_init(0)),
                                                  err(0)
{
  if (!mysql) {
    throw sqliface::DBEXC(mysql_error(mysql));
  }
  
  if (!mysql_real_connect(mysql, hostname, user, password, dbname, 0, 0, 0) ||
      mysql_query(mysql, "SET AUTOCOMMIT = 0;")) {
    mysql_close(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));
  }
}

myinterface::~myinterface(void) 
{
  if(mysql)
    mysql_close(mysql);
}

int myinterface::error(void) const
{
  return err;
}

void myinterface::connect(const char *dbname, 
                          const char *hostname, 
                          const char *user, 
                          const char *password)
{
  if (!mysql_real_connect(mysql,
                          hostname,
                          user,
                          password,
                          dbname,
                          0,
                          0,
                          0))
  {
    err = mysql_errno(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));
  }

  if (mysql_query(mysql,
                  "SET AUTOCOMMIT = 0;"))
  {
    err = mysql_errno(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));
  }
}

sqliface::query * myinterface::newquery()
{
  return new myquery(*this);
}

myquery::myquery(myinterface &face) : query_text(""),
                                      mysql(face.mysql),
                                      err(0)
{
}

myquery::myquery(const myquery& query) : query_text(query.query_text), 
                                         mysql(query.mysql),
                                         err(0)
{
}

myquery::~myquery(void) 
{
}

sqliface::query & myquery::operator<<(std::string s)
{
  std::string tmp = query_text + s;
  int pos = tmp.find_last_of('\n');

  if (pos == -1)
    pos = 0;

  query_text = tmp.substr(pos, tmp.size() - pos);
  return *this;
}

void myquery::exec(void)
{
  if (mysql_query(mysql,
                 query_text.c_str()))
  {
    err = mysql_errno(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));  
  }

  query_text = "";
}

int myquery::error(void) const
{
  return err;
}

sqliface::results * myquery::result(void)
{ 
  if (mysql_query(mysql,
                 query_text.c_str()))
  {
    err = mysql_errno(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));  
  }
  query_text = "";

  MYSQL_RES * result = mysql_store_result(mysql);

  if (!result)
  {
    err = mysql_errno(mysql);
    throw sqliface::DBEXC(mysql_error(mysql));  
  }

  return new myresults(result);
}

myresults::myresults(MYSQL_RES * res) : result(res),
                                        value(true),
                                        row(mysql_fetch_row(result))
{
  if(!row)
    value = false;
}

bool myresults::next(void)
{
  if (result)
    row = mysql_fetch_row(result);
  if (!row)
    value = false;

  //  return value;
}

myresults::~myresults() 
{
  if(result)
    mysql_free_result(result);
}

const std::string myresults::get(int field) const
{
  return std::string(row[field]);
}

const std::string myresults::get(const std::string& name) const
{
  mysql_field_seek(result, 0);
  MYSQL_FIELD * field = 0;
  int index = 0;
  while ((field = mysql_fetch_field(result)))
  {
    std::string field_name(field->name);
    if (name.size() == field_name.size() &&
        equal(name.begin(), name.end(), field->name, nocase_compare))
      //name == (std::string)field->name)
    {
      return std::string(row[index] ? row[index] : "NULL");
    }
    ++index;
  }
  throw sqliface::DBEXC("Unknown column " + name + ".");
}

int myresults::size(void) const
{
  return mysql_num_fields(result);
}

const std::string myresults::name(int index) const
{
  if (index<0 || index>size())
    throw sqliface::DBEXC("Index outside of range.");

  MYSQL_FIELD * field = mysql_fetch_field_direct(result, index);

  return field->name;
}

bool myresults::valid() const
{
  return value;
}

} // namespace bsq

extern "C" {
sqliface::interface *CreateDB()
{
  return new bsq::myinterface();
}
}
