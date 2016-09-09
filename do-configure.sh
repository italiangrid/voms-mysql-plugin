#!/bin/bash

set -ex

CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./configure --libdir=/usr/lib64
