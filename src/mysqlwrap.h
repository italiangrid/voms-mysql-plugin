/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it
 *
 * Copyright (c) Members of the EGEE Collaboration. 2002-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>
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
  bool operationGetAll         (long long, std::vector<std::string>&);
  bool operationGetRole        (long long, char *role, std::vector<std::string>&);
  bool operationGetGroups      (long long, std::vector<std::string>&);
  bool operationGetGroupAndRole(long long, char *group, char *role, std::vector<std::string>&);

  bool operationGetAllAttribs         (long long, std::vector<gattrib>&);
  bool operationGetRoleAttribs        (long long, char *role, std::vector<gattrib>&);
  bool operationGetGroupAttribs       (long long, std::vector<gattrib>&);
  bool operationGetGroupAndRoleAttribs(long long, char *group, char *role, std::vector<gattrib>&);
  int  operationGetVersion(void);

  void setError(int code, const std::string &message);
  bool executeQuery(MYSQL_STMT *, MYSQL_BIND *, MYSQL_BIND *, int);
  MYSQL_STMT *registerQuery(const char *);
  bool registerQueries(void);
  bool getFQANs(MYSQL_STMT *, MYSQL_BIND *, std::vector<std::string>&);
  bool  bindAndSetSize(MYSQL_STMT *, MYSQL_BIND *, int);
  long long getUIDASCII_v2(X509 *);
  long long getUIDASCII_v1(X509 *);
  long long getUID(X509 *);
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
  MYSQL_STMT *stmt_get_cid_v1;
  MYSQL_STMT *stmt_get_uid_v1;
  MYSQL_STMT *stmt_get_uid_v1_insecure;
  MYSQL_STMT *stmt_get_user_attributes;
  MYSQL_STMT *stmt_get_group_attributes;
  MYSQL_STMT *stmt_get_role_attributes;
  MYSQL_STMT *stmt_get_group_and_role_attributes;
  MYSQL_STMT *stmt_get_group_and_role_attributes_all;
  MYSQL_STMT *stmt_get_version;
  MYSQL_STMT *stmt_get_suspension_reason;

  bool insecure;
  int dbVersion;
  char *socket;
};

} //namespace bsq
