#ifndef __stream2string3_hh__
#define __stream2string3_hh__

using namespace std;
#include "../../src/autogen/config.h"

#ifdef HAVE_STRSTREAM_H
#include <strstream.h>
#else
#ifdef HAVE_STRSTREAM
#include <strstream>
#else
// Try anyway as a last ditch effort
#include <strstream.h>
//#error "No strstream found"
#endif
#endif

template<class Strng, class T>
Strng stream2string(const T &object) {
  ostrstream str;
  object.out_stream(str);
  str << ends;
  Strng s = str.str();
#ifdef __USLC__
  strstreambuf *tmpbuf = str.rdbuf();
  tmpbuf->freeze(0);
#else
  str.freeze(0);
#endif
  return s;
}

#endif
