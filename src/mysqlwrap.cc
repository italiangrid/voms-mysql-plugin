/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
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

#include "dbwrap.h"
#include "mysqlwrap.h"
#include <string>
#include <iostream>

static ResUse dummy;

namespace bsq {

myinterface::myinterface(const char *dbname, 
			 const char *hostname, 
			 const char *user, 
			 const char *password) : con(true), 
						 err(0)
{
  try 
  {
    con.connect(dbname, hostname, user, password);
  
    Query q = con.query();
    q << "SET AUTOCOMMIT = 0;";
    q.use();
  } 
  catch (BadQuery& bq) 
  {
    std::cout << bq.error << std::endl;
    throw sqliface::DBEXC(bq.error);
  } 
  catch (...) 
  {
    throw sqliface::DBEXC();
  }
  err = 0;

}

myinterface::myinterface() : con(true), err(0) {}


myinterface::~myinterface(void) {}

int myinterface::error(void) const
{
  return err;
}

void myinterface::connect(const char *dbname, const char *hostname, const char *user, const char *password)
{
  try 
  {
    con.connect(dbname, hostname, user, password);

    Query q = con.query();
    q << "SET AUTOCOMMIT = 0;";
    q.use();
  } 
  catch (BadQuery& bq) 
  {
    std::cout << bq.error << std::endl;
    throw sqliface::DBEXC(bq.error);
  } 
  catch (...) 
  {
    throw sqliface::DBEXC();
  }
  err = 0;
}

sqliface::query *myinterface::newquery()
{
  return new myquery(*this);
}

bsq::myquery::myquery(bsq::myinterface &face) : query_text(""), 
						c(&face.con),
						q(&face.con, true)  {}

myquery::myquery(const myquery& query) : query_text(query.query_text), 
					 c(query.c), 
					 q(query.q) {}

myquery::~myquery(void) {}

sqliface::query &myquery::operator<<(std::string s)
{
  std::string tmp = query_text + s;
  int    pos = tmp.find_last_of('\n');

  if (pos == -1)
    pos = 0;

  query_text = tmp.substr(pos, tmp.size() - pos);
  return *this;
}

void myquery::exec(void)
{
  q << query_text;
  query_text = "";

  try 
  {
    (void)q.use();
  } 
  catch (BadQuery& bq) 
  {
    std::cout << bq.error << std::endl;
    throw sqliface::DBEXC(bq.error);
  }
  catch (...) 
  {
    throw sqliface::DBEXC();
  }
}

int myquery::error(void) const
{
  return 0;
}

sqliface::results* myquery::result(void)
{ 
  q << query_text;
  query_text="";

  return new bsq::myresults(&q);
}

myresults::myresults(Query *q) : value(true)
{
  try 
  {
    res = q->use();
    row = res.fetch_row();

    if (row == Row())
      value = false;
  } 
  catch (BadQuery& bq) 
  {
    std::cout << bq.error << std::endl;
    throw sqliface::DBEXC(bq.error);
  }
  catch (...) 
  {
    throw sqliface::DBEXC();
  }
}

bool myresults::next(void)
{
  try 
  {
    row = res.fetch_row();
    if (row == Row())
      value = false;
  } 
  catch (...) 
  {
    throw sqliface::DBEXC();
  }
  return value;
}

myresults::~myresults() {}

const std::string myresults::get(int field) const
{
  return std::string(row[field]);
}

const std::string myresults::get(const std::string& name) const
{
  return std::string(row[name]);
}

int myresults::size(void) const
{
  return row.size();
}

const std::string myresults::name(int index) const
{
  return res.names(index);
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
