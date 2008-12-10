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
#include <vector>

extern "C" {
#include <mysql.h>
#include <mysqld_error.h>
#include <openssl/x509.h>
}

namespace bsq {
class myinterface : public sqliface::interface
{
public:

  myinterface();
  ~myinterface(void);

  bool connect(const char * dbname,
               const char * hostname,
               const char * user,
               const char * password);

  int error(void) const;
  bool reconnect();
  void close(void);
  bool setOption(int option, void *value);

  bool operation(int operation_type, void *result, ...);

  bool isConnected(void);
  char *errorMessage(void);

  sqliface::interface *getSession();
  void releaseSession(sqliface::interface *);

private:
  bool operationGetAll         (signed long int, std::vector<std::string>&);
  bool operationGetRole        (signed long int, char *role, std::vector<std::string>&);
  bool operationGetGroups      (signed long int, std::vector<std::string>&);
  bool operationGetGroupAndRole(signed long int, char *group, char *role, std::vector<std::string>&);

  bool operationGetAllAttribs         (signed long int, std::vector<gattrib>&);
  bool operationGetRoleAttribs        (signed long int, char *role, std::vector<gattrib>&);
  bool operationGetGroupAttribs       (signed long int, std::vector<gattrib>&);
  bool operationGetGroupAndRoleAttribs(signed long int, char *group, char *role, std::vector<gattrib>&);
  int  operationGetVersion(void);

  void setError(int code, const std::string &message);
  bool executeQuery(MYSQL_STMT *, MYSQL_BIND *, MYSQL_BIND *, int);
  MYSQL_STMT *registerQuery(const char *);
  bool registerQueries(void);
  bool getFQANs(MYSQL_STMT *, MYSQL_BIND *, std::vector<std::string>&);
  signed long int getUID_DER(X509 *);
  bool  bindAndSetSize(MYSQL_STMT *, MYSQL_BIND *, int);
  signed long int getUIDASCII_v2(X509 *);
  signed long int getUIDASCII_v1(X509 *);
  signed long int getUID(X509 *);
  bool getAttributes(MYSQL_STMT *, MYSQL_BIND *, std::vector<gattrib>&);
  void clearError();
  int getVersion();

  char *dbname;
  char *hostname;
  char *user;
  const char *password;
  char *host;
  int port;

  MYSQL * mysql;
  int err;
  bool isconnected;
  char error_msg[4096]; /* Local buffer. For longer messages, try allocating memory*/
  char *error_msg_heap;

  MYSQL_STMT *stmt_get_role;
  MYSQL_STMT *stmt_get_groups;
  MYSQL_STMT *stmt_get_groups_and_role;
  MYSQL_STMT *stmt_get_all;
  MYSQL_STMT *stmt_get_uid_v2;
  MYSQL_STMT *stmt_get_uid_v2_insecure;
  MYSQL_STMT *stmt_get_cid_v1;
  MYSQL_STMT *stmt_get_uid_v1;
  MYSQL_STMT *stmt_get_uid_v1_insecure;
  MYSQL_STMT *stmt_get_user_attributes;
  MYSQL_STMT *stmt_get_group_attributes;
  MYSQL_STMT *stmt_get_role_attributes;
  MYSQL_STMT *stmt_get_group_and_role_attributes;
  MYSQL_STMT *stmt_get_group_and_role_attributes_all;
  MYSQL_STMT *stmt_get_version;

  bool insecure;
  int dbVersion;
  char *socket;
};

} //namespace bsq
