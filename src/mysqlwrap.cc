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
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <string>
#include <algorithm>
#include <cctype>

static std::string translate(const std::string& name)
{
  std::string::size_type userid = name.find(std::string("/USERID="));
  std::string::size_type uid = name.find(std::string("/UID="));

  if (userid != std::string::npos)
    return name.substr(0, userid) + "/UID=" + name.substr(userid+8);
  else if (uid != std::string::npos)
    return name.substr(0, uid) + "/USERID=" + name.substr(uid+5);
  else
    return name;
}

namespace bsq {

sqliface::interface *myinterface::getSession()
{
  return this;
}

  void myinterface::releaseSession(sqliface::interface *face)
{
}

char *myinterface::errorMessage(void)
{
  if (!error_msg_heap)
    return error_msg;
  return error_msg_heap;
}

bool myinterface::operation(int operation, void *result, ...) 
{
  va_list va;
  va_start(va, result);

  clearError();
  int counter = 0;
  bool error = false;

  if (!result || !isConnected())
    return false;

  std::vector<std::string> *fqans = ((std::vector<std::string> *)result);
  std::vector<gattrib> *attrs = ((std::vector<gattrib> *)result);
  X509 *cert = NULL;
  signed long int uid = -1;
  char *group = NULL;
  char *role = NULL;

  error = false;
  /* Parse parameters: */
  switch(operation) {
  case OPERATION_GET_GROUPS_AND_ROLE:
  case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    group = va_arg(va, char *);
    role = va_arg(va, char *);
    if (uid == -1 || !group || !role)
      error = true;
    break;

  case OPERATION_GET_ROLE:
  case OPERATION_GET_ROLE_ATTRIBS:
    uid = va_arg(va, signed long int);
    role = va_arg(va, char *);
    if (uid == -1 || !role)
      error = true;
    break;
   
  case OPERATION_GET_GROUPS:
  case OPERATION_GET_ALL:
  case OPERATION_GET_GROUPS_ATTRIBS:
  case OPERATION_GET_ALL_ATTRIBS:
    uid = va_arg(va, signed long int);
    if (uid == -1)
      error = true;
    break;

  case OPERATION_GET_VERSION:
    break;

  case OPERATION_GET_USER:
    cert = va_arg(va, X509 *);
    if (!cert)
      error = true;
    break;

  default:
    error = true;
  }
  va_end(va);

  if (error) {
    setError(ERR_NO_PARAM, "Required parameter to sqliface::operation() is missing!");
    return false;
  }

  do {
    error = false;
    switch(operation) {
    case OPERATION_GET_VERSION:
      {
        *((int *)result) = operationGetVersion();
        return true;
      }
      break;

    case OPERATION_GET_USER:
      {
        signed long int res = getUID(cert);
        *((signed long int *)result) = res;
        if (res == -1)
          return false;
        return true;
      }
      break;

    case OPERATION_GET_ALL:
      {
        if (!operationGetAll(uid, *fqans))
          error = true;
      }
      break;

    case OPERATION_GET_GROUPS:
      {
        if (!operationGetGroups(uid, *fqans))
          error= true;
      }
      break;

    case OPERATION_GET_ROLE:
      {
        if (!operationGetRole(uid, role, *fqans))
          error = true;
      }
      break;
      
    case OPERATION_GET_GROUPS_AND_ROLE:
      {
        if (!operationGetGroupAndRole(uid, group, role, *fqans))
          error = true;
      }
      break;

    case OPERATION_GET_ALL_ATTRIBS:
      {
        if (!operationGetAllAttribs(uid, *attrs))
          error = true;
      }
      break;

    case OPERATION_GET_GROUPS_ATTRIBS:
      {
        if (!operationGetGroupAttribs(uid, *attrs))
          error= true;
      }
      break;

    case OPERATION_GET_ROLE_ATTRIBS:
      {
        if (!operationGetRoleAttribs(uid, role, *attrs))
          error = true;
      }
      break;
      
    case OPERATION_GET_GROUPS_AND_ROLE_ATTRIBS:
      {
        if (!operationGetGroupAndRoleAttribs(uid, group, role, *attrs))
          error = true;
      }
      break;
    }

    if (!error)
      break;
    else {
      if (this->err == ERR_DBERR) {
        int mysqlerror = mysql_errno(mysql);

        if ((mysqlerror == CR_SERVER_LOST)  && !counter) {
          /* try reconnecting and re-executing. */
          counter++;
          reconnect();
          continue;
        }
      }
      break;
    }
  } while (true);
  va_end(va);

  if (error)
    return false;

  return true;
}

void myinterface::clearError()
{
  free(error_msg_heap);
  error_msg_heap = NULL;
  err = 0;
}

void myinterface::setError(int code = 0, const std::string &str = "")
{
  clearError();

  err = code;

  if ((code == ERR_DBERR) && (str.empty())) {
    strcpy(error_msg, mysql_error(mysql));
    error_msg_heap = NULL;

    return;
  }

  if (!str.empty()) {
    if (str.size() < 4095) {
      strcpy(error_msg, str.c_str());
      error_msg_heap = NULL;
    }
    else {
      error_msg_heap = strdup(str.c_str());
    }
  }

  return;
}

myinterface::myinterface() : dbname(NULL),
                             hostname(NULL),
                             user(NULL),
                             password(NULL),
                             host(NULL),
                             port(0),
                             mysql(NULL),
                             err(0),
                             isconnected(false),
                             error_msg_heap(NULL),
                             stmt_get_role(NULL),
                             stmt_get_groups(NULL),
                             stmt_get_groups_and_role(NULL),
                             stmt_get_all(NULL),
                             stmt_get_uid_v2(NULL),
                             stmt_get_uid_v2_insecure(NULL),
                             stmt_get_cid_v1(NULL),
                             stmt_get_uid_v1(NULL),
                             stmt_get_uid_v1_insecure(NULL),
                             stmt_get_user_attributes(NULL),
                             stmt_get_group_attributes(NULL),
                             stmt_get_role_attributes(NULL),
                             stmt_get_group_and_role_attributes(NULL),
                             stmt_get_group_and_role_attributes_all(NULL),
                             stmt_get_version(NULL),
                             insecure(false),
                             dbVersion(1),
                             socket(NULL)
{
}
  

myinterface::~myinterface(void) 
{
  free(error_msg_heap);
  close();
}

void myinterface::close(void)
{
  if (mysql)
    mysql_close(mysql);
  mysql = NULL;
}

bool myinterface::reconnect()
{
  close();

  return connect(dbname, hostname, user, password);
}

int myinterface::error(void) const
{
  return err;
}

bool myinterface::connect(const char *dbname, 
                          const char *hostname, 
                          const char *user, 
                          const char *password)
{
  free(this->dbname);
  free(this->hostname);
  free(this->user);

  this->dbname   = strdup(dbname);
  this->hostname = strdup(hostname);
  this->user     = strdup(user);
  this->password = password;

  if (!this->dbname || !this->hostname || !this->user ||
      !this->password) {
    free(this->dbname);
    free(this->hostname);
    free(this->user);
    return false;
  }
  mysql = mysql_init(NULL);

  if (!mysql_real_connect(mysql, hostname, user, password, dbname, port, socket, 0)) {
    setError(ERR_NO_DB, mysql_error(mysql));
    return false;
  }

  if (getVersion() == -1) {
    close();
    mysql = NULL;
    return false;
  }

  bool result = registerQueries();
  if (result) {
    isconnected = true;
    return true;
  }
  else {
    close();
    mysql = NULL;
    return false;
  }
}

bool myinterface::setOption(int option, void *value)
{
  switch(option) {
  case OPTION_SET_PORT:
    if (!value)
      return false;
    port = *((int *)value);
    break;

  case OPTION_SET_INSECURE:
    if (!value)
      return false;
    insecure = *((bool *)value);
    break;

  case OPTION_SET_SOCKET:
    if (!value)
      return false;
    socket = strdup((char *)value);
    if (!value)
      return false;
    break;

  default:
    /* Ignore unknown options.  Allows new servers not to worry about
       what option what driver supports. */
    break;
  }
  return true;
}

bool myinterface::executeQuery(MYSQL_STMT *stmt, MYSQL_BIND *parameters, 
                                  MYSQL_BIND *results, int size)
{
  if (parameters)
    if (mysql_stmt_bind_param(stmt, parameters)) {
      setError(ERR_DBERR, mysql_stmt_error(stmt));
      return false;
    }

  if (mysql_stmt_execute(stmt) ||
      !bindAndSetSize(stmt, results, size)) {
    setError(ERR_DBERR, mysql_stmt_error(stmt));
    return false;
  }

  return true;
}

bool myinterface::operationGetRole(signed long int uid, char *role, std::vector<std::string> &fqans)
{
  MYSQL_BIND arguments[2];

  long unsigned int size = strlen(role);

  arguments[0].buffer_type = MYSQL_TYPE_STRING;
  arguments[0].buffer = role;
  arguments[0].is_null = 0;
  arguments[0].length = &size;

  arguments[1].buffer_type = MYSQL_TYPE_LONG;
  arguments[1].buffer = (char *)&uid;
  arguments[1].is_null = 0;
  arguments[1].length = 0;

  return getFQANs(stmt_get_role, arguments, fqans) && operationGetGroups(uid, fqans);
}

bool myinterface::operationGetGroups(signed long int uid, std::vector<std::string> &fqans)
{
  MYSQL_BIND arguments[1];

  arguments[0].buffer_type = MYSQL_TYPE_LONG;
  arguments[0].buffer = (char *)&uid;
  arguments[0].is_null = 0;
  arguments[0].length = 0;

  return getFQANs(stmt_get_groups, arguments, fqans);
}

bool myinterface::operationGetGroupAndRole(signed long int uid, char *group, 
                                           char *role, std::vector<std::string> &fqans)
{
  MYSQL_BIND arguments[3];

  unsigned long int size1 = strlen(group);
  unsigned long int size2 = strlen(role);

  memset(&(arguments[0]), 0, sizeof(MYSQL_BIND));
  memset(&(arguments[1]), 0, sizeof(MYSQL_BIND));
  memset(&(arguments[2]), 0, sizeof(MYSQL_BIND));

  arguments[0].buffer_type = MYSQL_TYPE_STRING;
  arguments[0].buffer = group;
  arguments[0].is_null = 0;
  arguments[0].length = &size1;

  arguments[1].buffer_type = MYSQL_TYPE_STRING;
  arguments[1].buffer = role;
  arguments[1].is_null = 0;
  arguments[1].length = &size2;

  arguments[2].buffer_type = MYSQL_TYPE_LONG;
  arguments[2].buffer = (char *)&uid;
  arguments[2].is_null = 0;
  arguments[2].length = 0;

  return getFQANs(stmt_get_groups_and_role, arguments, fqans) &&
    operationGetGroups(uid, fqans);
}

bool myinterface::operationGetAll(signed long int uid, std::vector<std::string> &fqans)
{
  MYSQL_BIND parameter[1];
  //  memset(parameter, 0, sizeof(parameter));

  memset(&(parameter[0]), 0, sizeof(MYSQL_BIND));

  parameter[0].buffer = (char *)&uid;
  parameter[0].buffer_type = MYSQL_TYPE_LONG;
  parameter[0].is_null = 0;
  parameter[0].length = 0;

  return getFQANs(stmt_get_all, parameter, fqans);
}

bool myinterface::operationGetGroupAndRoleAttribs(signed long int uid, char *group,
                                                  char *role,
                                                  std::vector<gattrib> &attrs)
{
  if (!group || !role) {
    setError(ERR_NO_PARAM, "Parameter unset.");
    return false;
  }

  MYSQL_BIND parameter[3];
  //  memset(parameter, 0, sizeof(parameter));

  long unsigned int sizerole = strlen(role);
  long unsigned int sizegroup = strlen(group);

  memset(&(parameter[0]), 0, sizeof(MYSQL_BIND));
  memset(&(parameter[1]), 0, sizeof(MYSQL_BIND));
  memset(&(parameter[2]), 0, sizeof(MYSQL_BIND));

  parameter[0].buffer = (char *)&uid;
  parameter[0].buffer_type = MYSQL_TYPE_LONG;
  parameter[0].is_null = 0;
  parameter[0].length = 0;
  parameter[1].buffer = role;
  parameter[1].buffer_type = MYSQL_TYPE_STRING;
  parameter[1].is_null = 0;
  parameter[1].length = &sizerole;
  parameter[2].buffer = group;
  parameter[2].buffer_type = MYSQL_TYPE_STRING;
  parameter[2].is_null = 0;
  parameter[2].length = &sizegroup;

  clearError();

  return getAttributes(stmt_get_user_attributes, parameter, attrs) &&
    getAttributes(stmt_get_group_attributes, parameter, attrs) &&
    getAttributes(stmt_get_group_and_role_attributes, parameter, attrs);
}

bool myinterface::operationGetGroupAttribs(signed long int uid,
                                           std::vector<gattrib> &attrs)
{
  MYSQL_BIND parameter[1];
  //  memset(parameter, 0, sizeof(parameter));

  memset(&(parameter[0]), 0, sizeof(MYSQL_BIND));

  parameter[0].buffer = (char *)&uid;
  parameter[0].buffer_type = MYSQL_TYPE_LONG;
  parameter[0].is_null = 0;
  parameter[0].length = 0;

  clearError();

  return getAttributes(stmt_get_user_attributes, parameter, attrs) &&
    getAttributes(stmt_get_group_attributes, parameter, attrs);
}

bool myinterface::operationGetRoleAttribs(signed long int uid, char *role,
                                           std::vector<gattrib> &attrs)
{
  MYSQL_BIND parameter[2];
  //  memset(parameter, 0, sizeof(parameter));
  long unsigned int sizerole = strlen(role);

  memset(&(parameter[0]), 0, sizeof(MYSQL_BIND));
  memset(&(parameter[1]), 0, sizeof(MYSQL_BIND));

  parameter[0].buffer = role;
  parameter[0].buffer_type = MYSQL_TYPE_STRING;
  parameter[0].is_null = 0;
  parameter[0].length = &sizerole;
  parameter[1].buffer = (char *)&uid;
  parameter[1].buffer_type = MYSQL_TYPE_LONG;
  parameter[1].is_null = 0;
  parameter[1].length = 0;

  clearError();

  return getAttributes(stmt_get_user_attributes, parameter, attrs) &&
    getAttributes(stmt_get_role_attributes, parameter, attrs);
}


bool myinterface::operationGetAllAttribs(signed long int uid,
                                         std::vector<gattrib> &attrs)
{
  MYSQL_BIND parameter[1];
  //  memset(parameter, 0, sizeof(parameter));

  memset(&(parameter[0]), 0, sizeof(MYSQL_BIND));

  parameter[0].buffer = (char *)&uid;
  parameter[0].buffer_type = MYSQL_TYPE_LONG;
  parameter[0].is_null = 0;
  parameter[0].length = 0;

  clearError();

  return getAttributes(stmt_get_user_attributes, parameter, attrs) &&
    getAttributes(stmt_get_group_attributes, parameter, attrs) &&
    getAttributes(stmt_get_group_and_role_attributes_all, parameter, attrs);
}

MYSQL_STMT *myinterface::registerQuery(char *query)
{
  MYSQL_STMT *stmt = NULL;

  if (stmt = mysql_stmt_init(mysql))
    if (mysql_stmt_prepare(stmt, query, strlen(query))) {
      setError(ERR_DBERR, mysql_stmt_error(stmt));
      mysql_stmt_close(stmt);
      stmt = NULL;
    }
    
  return stmt;
}

bool myinterface::registerQueries(void)
{

  stmt_get_group_and_role_attributes_all = registerQuery(
    "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM attributes, role_attrs, groups, roles, m "
    "WHERE attributes.a_id = role_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = ? AND "
    "m.rid = roles.rid AND "
    "role_attrs.g_id = m.gid AND "
    "role_attrs.r_id = m.rid");

  stmt_get_group_and_role_attributes = registerQuery(
    "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM attributes, role_attrs, groups, roles, m "
    "WHERE attributes.a_id = role_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = ? AND "
    "m.rid = roles.rid AND "
    "roles.role = ? AND "
    "groups.dn = ? AND "
    "role_attrs.g_id = m.gid AND "
    "role_attrs.r_id = m.rid");

  stmt_get_group_attributes = registerQuery(
    "SELECT attributes.a_name, group_attrs.a_value, groups.dn, NULL "
    "FROM attributes, group_attrs, groups, m "
    "WHERE attributes.a_id = group_attrs.a_id AND "
    "groups.gid = m.gid AND "
    "m.userid = ? AND "
    "m.rid is NULL AND "
    "group_attrs.g_id = m.gid");

  stmt_get_user_attributes = registerQuery(
    "SELECT attributes.a_name, usr_attrs.a_value, NULL, NULL "
    "FROM attributes, usr_attrs "
    "WHERE attributes.a_id = usr_attrs.a_id AND "
    "usr_attrs.u_id = ?");

  stmt_get_role = registerQuery(
    "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "roles.role = ? AND m.userid = ?");

  stmt_get_role_attributes = registerQuery(
    "SELECT attributes.a_name, role_attrs.a_value, groups.dn, roles.role "
    "FROM m "
    "INNER JOIN groups ON m.gid = groups.gid "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "INNER JOIN role_attrs on groups.gid = role_attrs.g_id "
    "INNER JOIN attributes on attributes.a_id = role_attrs.a_id "
    "WHERE role_attrs.r_id = roles.rid AND "
    "roles.role = ? AND "
    "m.userid = ?");

  stmt_get_groups = registerQuery(
    "SELECT groups.dn, NULL FROM groups, m "
    "WHERE groups.gid = m.gid AND "
    "m.userid = ?");

  stmt_get_groups_and_role = registerQuery(
    "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "groups.dn = ? AND roles.role = ? AND "
    "m.userid = ?");

  stmt_get_all = registerQuery(
    "SELECT groups.dn, role FROM groups, m "
    "LEFT JOIN roles ON roles.rid = m.rid "
    "WHERE groups.gid = m.gid AND "
    "m.userid = ?");

  if (dbVersion == 3)
    stmt_get_uid_v2 = registerQuery(
      "SELECT certificate.id, certificate.suspended, "
      "certificate.suspended_reason "
      "FROM certificate, ca "
      "WHERE certificate.subject_der = ? AND "
      "certificate.ca_id = ca.id AND "
      "ca.subject_der = ?");

  if (dbVersion == 3)
    stmt_get_uid_v2_insecure = registerQuery(
      "SELECT certificate.id, certificate.suspended, "
      "certificate.suspended_reason "
      "FROM certificate, ca "
      "WHERE certificate.subject_der = ? AND "
      "ca.subject_der = ?");

  (dbVersion == 3 ?
   stmt_get_cid_v1 = registerQuery(
     "SELECT id FROM ca WHERE subject_string = ?") :
   stmt_get_cid_v1 = registerQuery(
     "SELECT cid FROM ca WHERE ca.ca = ?"));

  (dbVersion == 3 ?
   stmt_get_uid_v1 = registerQuery(
    "SELECT id FROM certificate WHERE subject_string = ? AND ca_id = ?") :
   stmt_get_uid_v1 = registerQuery(
    "SELECT userid FROM usr WHERE dn = ? AND ca = ?"));

  (dbVersion == 3 ?
   stmt_get_uid_v1_insecure = registerQuery(
     "SELECT id FROM certificate WHERE subject_string = ?") :
   stmt_get_uid_v1_insecure = registerQuery(
     "SELECT userid FROM usr WHERE usr.dn = ?"));

  if (!stmt_get_role ||
      !stmt_get_groups ||
      !stmt_get_groups_and_role ||
      !stmt_get_all ||
      ((dbVersion == 3) && !stmt_get_uid_v2) ||
      ((dbVersion == 3) && !stmt_get_uid_v2_insecure) ||
      !stmt_get_cid_v1 ||
      !stmt_get_uid_v1 ||
      !stmt_get_uid_v1_insecure ||
      !stmt_get_user_attributes ||
      !stmt_get_group_attributes ||
      !stmt_get_role_attributes ||
      !stmt_get_group_and_role_attributes ||
      !stmt_get_group_and_role_attributes_all) {
    if (stmt_get_role)
      mysql_stmt_close(stmt_get_role);
      
    if (stmt_get_groups)
      mysql_stmt_close(stmt_get_groups);
      
    if (stmt_get_groups_and_role)
      mysql_stmt_close(stmt_get_groups_and_role);
      
    if (stmt_get_all)
      mysql_stmt_close(stmt_get_all);
      
    if (stmt_get_uid_v2)
      mysql_stmt_close(stmt_get_uid_v2);
      
    if (stmt_get_uid_v2_insecure)
      mysql_stmt_close(stmt_get_uid_v2_insecure);
      
    if (stmt_get_cid_v1)
      mysql_stmt_close(stmt_get_cid_v1);
      
    if (stmt_get_uid_v1)
      mysql_stmt_close(stmt_get_uid_v1);
      
    if (stmt_get_uid_v1_insecure)
      mysql_stmt_close(stmt_get_uid_v1_insecure);

    if (stmt_get_user_attributes)
      mysql_stmt_close(stmt_get_user_attributes);
      
    if (stmt_get_group_attributes)
      mysql_stmt_close(stmt_get_group_attributes);

    if (stmt_get_role_attributes)
      mysql_stmt_close(stmt_get_role_attributes);

    if (stmt_get_group_and_role_attributes)
      mysql_stmt_close(stmt_get_group_and_role_attributes);

    if (stmt_get_group_and_role_attributes_all)
      mysql_stmt_close(stmt_get_group_and_role_attributes_all);

    return false;
  }

  return true;
}

bool myinterface::getFQANs(MYSQL_STMT *stmt, MYSQL_BIND *parameters, std::vector<std::string> &fqans)
{
  MYSQL_BIND results[2];

  /* Temporary binding for first binding call */
  memset(results, 0, sizeof(results));

  memset(&(results[0]), 0, sizeof(results[0]));
  memset(&(results[1]), 0, sizeof(results[1]));

  results[0].buffer_type = MYSQL_TYPE_STRING;
  results[0].buffer = 0;
  results[0].buffer_length = 0;
  results[0].length = 0;

  results[1].buffer_type = MYSQL_TYPE_STRING;
  results[1].buffer = 0;
  results[1].buffer_length = 0;
  results[1].length = 0;

  /* Execute query */
  if (!executeQuery(stmt, parameters, results, 2)) {
    setError(ERR_DBERR, mysql_stmt_error(stmt));
    return false;
  }

  /* Read data */
  unsigned long numberOfRows = (unsigned long)mysql_stmt_num_rows(stmt);

  for (int i = 0; i < numberOfRows; i++) {
    mysql_stmt_fetch(stmt);
    mysql_stmt_fetch_column(stmt, &(results[0]),0,0);
    mysql_stmt_fetch_column(stmt, &(results[1]),1,0);

    /* Now I've got the results: */
    std::string fqan = std::string((char *)(results[0].buffer), *(results[0].length)) +
      (results[1].is_null || !(results[1].buffer) ||
       ((char*)results[1].buffer)[0] == '\0' ? "" : std::string("/Role=") +
       std::string((char *)(results[1].buffer), *(results[1].length)));

    fqans.push_back(fqan);
  }
  free(results[0].buffer);
  free(results[1].buffer);

  return true;
}

signed long int myinterface::getUID_DER(X509 *certificate)
{
  X509_NAME *subjname = X509_get_subject_name(certificate);
  X509_NAME *issname  = X509_get_issuer_name(certificate);

  if (!subjname || !issname) {
    setError(ERR_X509, "Unable to extract subject data from certificate.");
    return -1;
  }

  /* First try looking into blob */

  /* Determine subject and issuer blob. */
  int   lensubj = i2d_X509_NAME(subjname, NULL);
  unsigned char *buffersubj = (unsigned char*)malloc(lensubj);
  char *escaped_buffer_subj = (char*)malloc(lensubj*2+1);

  if (!buffersubj || !escaped_buffer_subj) {
    free(buffersubj);
    free(escaped_buffer_subj);
    setError(ERR_NO_MEMORY, "Unable to allocate necessary memory.");
    return -1;
  }

  (void)i2d_X509_NAME(subjname, &buffersubj);
  long unsigned int newlen_subj = mysql_real_escape_string(mysql, (char*)buffersubj, 
                                             escaped_buffer_subj, lensubj);
  free(buffersubj);

  long unsigned int newlen_iss = 0;
  char *escaped_buffer_iss = NULL;

  if (!insecure) {
    int leniss  = i2d_X509_NAME(issname, NULL);
    unsigned char *bufferiss  = (unsigned char*)malloc(leniss);
    escaped_buffer_iss = (char*)malloc(leniss*2+1);

    if (!bufferiss || !escaped_buffer_iss) {
      free(bufferiss);
      free(escaped_buffer_iss);
      setError(ERR_NO_MEMORY, "Unable to allocate necessary memory.");
      return -1;
    }

    (void)i2d_X509_NAME(issname, &bufferiss);
    newlen_iss  = mysql_real_escape_string(mysql, (char *)bufferiss, 
                                           escaped_buffer_iss, leniss);
  
    free(bufferiss);
  }

  /* now construct query. */

  MYSQL_BIND results[3];
  memset(results, 0 ,sizeof(results));

  MYSQL_BIND parameter[2];
  memset(parameter, 0 ,sizeof(parameter));
  
  int result;

  parameter[0].buffer = escaped_buffer_subj;
  parameter[0].length = &newlen_subj;
  parameter[0].buffer_type = MYSQL_TYPE_BLOB;
  parameter[0].is_null = 0;

  parameter[1].buffer = escaped_buffer_iss;
  parameter[1].length = &newlen_iss;
  parameter[1].buffer_type = MYSQL_TYPE_BLOB;
  parameter[1].is_null = 0;


  MYSQL_STMT *stmt;
  if (insecure)
    stmt = stmt_get_uid_v2_insecure;
  else
    stmt = stmt_get_uid_v2;

  int id;
  int suspended;

  results[0].buffer = (char*)&id;
  results[0].buffer_type = MYSQL_TYPE_LONG;
  results[1].buffer = (char*)&suspended;
  results[1].buffer_type = MYSQL_TYPE_TINY;
  results[2].buffer = 0;
  results[2].buffer_type = MYSQL_TYPE_BLOB;
  results[2].buffer_length = 0;

  result = executeQuery(stmt_get_uid_v2_insecure, parameter, results, 3);

  if (result) {
    if (!mysql_stmt_fetch(stmt)) {
      if (suspended) {
        setError(ERR_ACCOUNT_SUSPENDED, std::string((char *)(results[2].buffer),
                                                    results[2].buffer_length));
        free(results[2].buffer);
        return -1;
      }
      return id;
    }
  }
  setError(ERR_USER_UNKNOWN, "User Unknown");

  return -1;
}

bool myinterface::bindAndSetSize(MYSQL_STMT *stmt, MYSQL_BIND *outputs, int size)
{
  my_bool value = true;
  MYSQL_RES *result = NULL;
  MYSQL_FIELD *field = NULL;

  mysql_stmt_attr_set(stmt, STMT_ATTR_UPDATE_MAX_LENGTH,  &value);

  if (mysql_stmt_bind_result(stmt, outputs) || 
      mysql_stmt_store_result(stmt) ||
      !(result = mysql_stmt_result_metadata(stmt))) {
    setError(ERR_DBERR, mysql_stmt_error(stmt));
    return false;
  }
  
  for (int i = 0; i < size; i++) {
    field = mysql_fetch_field(result);
    if (field->type == MYSQL_TYPE_BLOB ||
        field->type == MYSQL_TYPE_VAR_STRING ||
        field->type == MYSQL_TYPE_LONG_BLOB ||
        field->type == MYSQL_TYPE_MEDIUM_BLOB ||
        field->type == MYSQL_TYPE_TINY_BLOB ||
        field->type == MYSQL_TYPE_STRING) {
      outputs[i].buffer_length = field->max_length;
      outputs[i].buffer = (char *)malloc(field->max_length);
      if (!outputs[i].buffer) {
        for (int j = 0; j < i; j++) {
          if (outputs[j].buffer_type == MYSQL_TYPE_BLOB ||
              outputs[j].buffer_type == MYSQL_TYPE_STRING ||
              outputs[j].buffer_type == MYSQL_TYPE_VAR_STRING ||
              outputs[j].buffer_type == MYSQL_TYPE_LONG_BLOB ||
              outputs[j].buffer_type == MYSQL_TYPE_MEDIUM_BLOB ||
              outputs[j].buffer_type == MYSQL_TYPE_TINY_BLOB ||
              outputs[j].buffer_type == MYSQL_TYPE_STRING)
            free(outputs[j].buffer);
          setError(ERR_NO_MEMORY, "Not enoguh memory");
          return false;
        }
      }
    }
  }
  return true;
}

signed long int myinterface::getUIDASCII_v2(X509 *cert)
{
  char *caname = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
  char *dnname = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

  if (!caname || !dnname) {
    OPENSSL_free(caname);
    OPENSSL_free(dnname);
    setError(ERR_NO_MEMORY, "Unable to allocate the necessary memory.");
    return -1;
  }

  std::string ca = std::string(caname);
  std::string dn = std::string(dnname);
  std::string::size_type pos = 0;

  while((pos = ca.find_first_of("'", pos+3)) != std::string::npos)
    ca.insert(pos, "'");

  pos = 0;
  while((pos = dn.find_first_of("'", pos+3)) != std::string::npos)
    dn.insert(pos, "'");

  OPENSSL_free(caname);
  OPENSSL_free(dnname);

  int cid;

  if (!insecure) {
    MYSQL_BIND parameter[2];
    memset(parameter, 0, sizeof(parameter));

    parameter[0].buffer = (void *)ca.c_str();
    parameter[0].buffer_length = strlen(ca.c_str());
    parameter[0].buffer_type = MYSQL_TYPE_STRING;
    parameter[0].is_null = 0;

    MYSQL_BIND result[0];
    memset(result, 0, sizeof(result));
    result[0].buffer=(char *)&cid;
    result[0].buffer_type = MYSQL_TYPE_LONG;

    /* Determine CID */

    if (!executeQuery(stmt_get_cid_v1, parameter, result, 1)) {
      ca = translate(ca);

      parameter[0].buffer = (void *)(ca.c_str());
      parameter[0].buffer_length = ca.size();
      parameter[0].buffer_type = MYSQL_TYPE_STRING;
      parameter[0].is_null = 0;

      if (!executeQuery(stmt_get_cid_v1, parameter, result, 1)) {
        setError(ERR_NO_CA, "CA is unregistered");
        return -1;
      }
    }

    if (mysql_stmt_fetch(stmt_get_cid_v1) == MYSQL_NO_DATA) {
      setError(ERR_NO_CA, "CA is unregistered");
      return -1;
    }

    /* now cid has the ca_id */
  }

  /* Determine UID */

  MYSQL_BIND parameter[2];

  parameter[0].buffer = (void*)dn.c_str();
  parameter[0].buffer_length = dn.size();
  parameter[0].buffer_type = MYSQL_TYPE_STRING;
  parameter[0].is_null = 0;

  parameter[1].buffer = (char*)&cid;
  parameter[1].buffer_length = 0;
  parameter[1].buffer_type = MYSQL_TYPE_LONG;
  parameter[1].is_null = 0;
  
  bool result;

  MYSQL_STMT *stmt = NULL;

  if (insecure)
    stmt = stmt_get_uid_v2_insecure;
  else
    stmt = stmt_get_uid_v2;

  MYSQL_BIND res[0];

  res[0].buffer = 0;
  res[0].buffer_type = MYSQL_TYPE_STRING;
  res[0].buffer_length = 0;

  result = executeQuery(stmt, parameter, res, 1);

  if (!result) {
    dn = translate(dn);

    parameter[0].buffer = (void*)dn.c_str();
    parameter[0].buffer_length = dn.size();
    parameter[0].buffer_type = MYSQL_TYPE_STRING;
    parameter[0].is_null = 0;

    result = executeQuery(stmt, parameter, res, 1);

    if (!result) {
      setError(ERR_USER_UNKNOWN, "USER is unregistered");
      return -1;
    }
  }
  if (mysql_stmt_fetch(stmt)) {
      setError(ERR_USER_UNKNOWN, "USER is unregistered");
      return -1;
  }

  return cid;
}

signed long int myinterface::getUIDASCII_v1(X509 *cert)
{
  char *caname = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
  char *dnname = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);

  if (!caname || !dnname) {
    OPENSSL_free(caname);
    OPENSSL_free(dnname);
    setError(ERR_NO_MEMORY, "Unable to allocate the necessary memory.");
    return -1;
  }

  std::string ca = std::string(caname);
  std::string dn = std::string(dnname);
  OPENSSL_free(caname);
  OPENSSL_free(dnname);

  MYSQL_BIND parameter[2];
  MYSQL_BIND result[1];
  
  memset(&(parameter[0]), 0, sizeof(parameter[0]));
  memset(&(parameter[1]), 0, sizeof(parameter[1]));
  memset(&(result[0]), 0, sizeof(result[0]));

  int cid;

  result[0].buffer = (char *)&cid;
  result[0].buffer_type = MYSQL_TYPE_LONG;

  if (!insecure) {
  /* Determine CID */

    parameter[0].buffer = (void*)ca.c_str();
    parameter[0].buffer_length = ca.size();
    parameter[0].buffer_type = MYSQL_TYPE_STRING;
    parameter[0].is_null = 0;

    if (!executeQuery(stmt_get_cid_v1, parameter, result, 1)) {
      ca = translate(ca);

      parameter[0].buffer = (void*)ca.c_str();
      parameter[0].buffer_length = ca.size();
      parameter[0].buffer_type = MYSQL_TYPE_STRING;
      parameter[0].is_null = 0;

      if (!executeQuery(stmt_get_cid_v1, parameter, result, 1)) {
        setError(ERR_NO_CA, "CA is unregistered");
        return -1;
      }
    }
    if (mysql_stmt_fetch(stmt_get_cid_v1) == MYSQL_NO_DATA) {
      setError(ERR_NO_CA, "CA is unregistered");
      return -1;
    }

    /* now cid has the ca_id */
  }

  /* Determine UID */

  memset(&parameter, 0, sizeof(parameter));
  parameter[0].buffer = (void*)dn.c_str();
  parameter[0].buffer_length = dn.size();
  parameter[0].buffer_type = MYSQL_TYPE_STRING;
  parameter[0].is_null = 0;

  parameter[1].buffer = (char*)&cid;
  parameter[1].buffer_length = 0;
  parameter[1].buffer_type = MYSQL_TYPE_LONG;
  parameter[1].is_null = 0;

  MYSQL_STMT *stmt = NULL;

  if (insecure)
    stmt = stmt_get_uid_v1_insecure;
  else
    stmt = stmt_get_uid_v1;

  MYSQL_BIND res[1];

  memset(res, 0, sizeof(res));
  memset(&(res[0]), 0, sizeof(res[0]));
  res[0].buffer = (char *)&cid;
  res[0].buffer_type = MYSQL_TYPE_LONG;

  if (!executeQuery(stmt, parameter, res, 1)) {
    dn = translate(dn);

    memset(&(parameter[0]), 0, sizeof(parameter[0]));
    parameter[0].buffer = (void *)dn.c_str();
    parameter[0].buffer_length = dn.size();
    parameter[0].buffer_type = MYSQL_TYPE_STRING;
    parameter[0].is_null = 0;

    if (!executeQuery(stmt, parameter, res, 1)) {
      setError(ERR_NO_CA, "USER is unregistered");
      return -1;
    }
  }

  if (mysql_stmt_fetch(stmt)) {
      setError(ERR_NO_CA, "USER is unregistered");
      return -1;
  }

  return cid;
}

bool myinterface::isConnected(void)
{
  return isconnected;
}

signed long int myinterface::getUID(X509 *certificate)
{
  if (!certificate) {
    setError(ERR_NO_IDDATA, "No Identifying data passed.");
    return -1;
  }

  if (!isconnected) {
    setError(ERR_NO_DB, "Not Connected to DB.");
    return -1;
  }

  signed long int uid = -1;

  if (dbVersion == 3 ) {
    //    uid = getUID_DER(certificate);
    if (uid == -1) {
      //      if (err == ERR_USER_UNKNOWN)
      return getUIDASCII_v2(certificate);
    }
    else 
      return uid;
  }
  else {
    (void)getUIDASCII_v1(certificate);
    return 1;
  }
}

int myinterface::operationGetVersion(void)
{
  return dbVersion;
}

int myinterface::getVersion(void)
{

  MYSQL_STMT *stmt = registerQuery("SELECT version FROM version");

  if (stmt) {
    MYSQL_BIND result[1];

    memset(result, 0, sizeof(result));

    long unsigned int size = 0;

    result[0].buffer_type = MYSQL_TYPE_LONG;
    result[0].buffer = (char *)&size;
    result[0].is_null = 0;
    result[0].length = 0;

    if (!executeQuery(stmt, NULL, result, 1)) {
      setError(ERR_DBERR, mysql_stmt_error(stmt));
      return -1;
    }

    mysql_stmt_fetch(stmt);
    mysql_stmt_close(stmt);

    return dbVersion = size;
  }
  else {
    setError(ERR_DBERR, mysql_stmt_error(stmt));
    return -1;
  }
}

bool myinterface::getAttributes(MYSQL_STMT *stmt,
                                MYSQL_BIND *parameters,
                                std::vector<gattrib> &attrs)
{
  MYSQL_BIND results[4];
  unsigned long int len[4];

  len[1] = len[2] = len[3] = len[4] = 0;
  /* Temporary binding for first binding call */
  memset(results, 0, sizeof(results));

  results[0].buffer_type = MYSQL_TYPE_STRING;
  results[0].buffer = 0;
  results[0].buffer_length = 0;
  results[0].length = &(len[0]);

  results[1].buffer_type = MYSQL_TYPE_STRING;
  results[1].buffer = 0;
  results[1].buffer_length = 0;
  results[1].length = &(len[1]);

  results[2].buffer_type = MYSQL_TYPE_STRING;
  results[2].buffer = 0;
  results[2].buffer_length = 0;
  results[2].length = &(len[2]);

  results[3].buffer_type = MYSQL_TYPE_STRING;
  results[3].buffer = 0;
  results[3].buffer_length = 0;
  results[3].length = &(len[3]);

  /* Execute query */
  if (!executeQuery(stmt, parameters, results, 4)) {
    setError(ERR_DBERR, mysql_stmt_error(stmt));
    return false;
  }

  /* Read data */
  unsigned long numberOfRows = (unsigned long)mysql_stmt_num_rows(stmt);

  for (int i = 0; i < numberOfRows; i++) {
    mysql_stmt_fetch(stmt);
    mysql_stmt_fetch_column(stmt, &(results[0]), 0, 0);
    mysql_stmt_fetch_column(stmt, &(results[1]), 1, 0);
    mysql_stmt_fetch_column(stmt, &(results[2]), 2, 0);
      
    gattrib ga;
    ga.name      = std::string((char*)(results[0].buffer), *(results[0].length));

    if (!(results[1].is_null || !results[1].buffer || 
          ( ((char *)(results[1].buffer))[0]) == '\0'))
      ga.value = std::string( ((char *)(results[1].buffer)),
                              (std::string::size_type)(*(results[1].length)));
//     ga.value     = (results[1].is_null || (!results[1].buffer) ||
//                     ((char *)results[1].buffer)[0] == '\0' ? "" :
//                     std::string((char*)(results[1].buffer)), (std::string::size_type)(*(results[1].length)));

    if (!(results[2].is_null || (!results[2].buffer) ||
          (((char *)results[2].buffer)[0] == '\0')))
      ga.qualifier = std::string( ((char*)(results[2].buffer)),
                                  (std::string::size_type)(*(results[2].length)));
//     ga.qualifier = (results[2].is_null || (!results[2].buffer) ||
//                     ((char *)results[2].buffer)[0] == '\0' ? "" :
//                     std::string((char*)(results[2].buffer)), (std::string::size_type)(*(results[2].length)));
    attrs.push_back(ga);
  }
  return true;
}
} // namespace bsq

extern "C" {

sqliface::interface *CreateDB()
{
  return new bsq::myinterface();
}

int getDBInterfaceVersion() 
{
    return 3;
}

int getDBInterfaceVersionMinor()
{
  return 1;
}

} /* extern "C" */
