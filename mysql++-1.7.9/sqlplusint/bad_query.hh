#ifndef __BAD_QUERY_EXCEPT__KK
#define __BAD_QUERY_EXCEPT__KK
#include <string>

//: Exception thrown when a BadQuery is encountered
struct BadQuery {
  BadQuery(string er) : error(er) {}
  string error; //: The error message
};

#endif
