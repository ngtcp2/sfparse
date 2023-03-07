#!/bin/bash -eu

autoreconf -i
./configure
make -j$(nproc)

$CXX $CXXFLAGS -std=c++17 -I. \
     fuzz/parser.cc -o $OUT/parser \
     $LIB_FUZZING_ENGINE .libs/libsfparse.a

zip -j $OUT/fuzz_parser_seed_corpus.zip fuzz/corpus/parser/*
