#!/bin/bash -eu

autoreconf -i
./configure --disable-dependency-tracking CFLAGS="-g -O2 -mavx2"
make -j$(nproc)

$CXX $CXXFLAGS -std=c++17 -I. \
     fuzz/parser.cc -o $OUT/parser \
     $LIB_FUZZING_ENGINE .libs/libsfparse.a

zip -j $OUT/parser_seed_corpus.zip fuzz/corpus/parser/*
