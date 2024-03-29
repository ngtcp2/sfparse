# sfparse
#
# Copyright (c) 2023 sfparse contributors
# Copyright (c) 2019 nghttp3 contributors
# Copyright (c) 2016 ngtcp2 contributors
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
SUBDIRS = doc

EXTRA_DIST = munit/COPYING

ACLOCAL_AMFLAGS = -I m4

# Format source files using clang-format.  Don't format source files
# under third-party directory since we are not responsible for their
# coding style.
clang-format:
	CLANGFORMAT=`git config --get clangformat.binary`; \
	test -z $${CLANGFORMAT} && CLANGFORMAT="clang-format"; \
	$${CLANGFORMAT} -i *.{c,h} fuzz/*.cc

AM_CFLAGS = $(WARNCFLAGS)
AM_CPPFLAGS = -I$(srcdir) -I$(srcdir)/munit

lib_LTLIBRARIES = libsfparse.la

libsfparse_la_SOURCES = sfparse.c sfparse.h
libsfparse_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

include_HEADERS = sfparse.h

noinst_PROGRAMS = examples

examples_SOURCES = examples.c
examples_LDADD = $(top_builddir)/libsfparse.la

check_PROGRAMS = test

test_SOURCES = sfparse_test_main.c sfparse_test.c sfparse_test.h \
	munit/munit.c munit/munit.h

test_CFLAGS = $(WARNCFLAGS) -I$(top_srcdir)
test_LDADD = $(top_builddir)/.libs/sfparse.o
test_LDFLAGS = -static

TESTS = test
