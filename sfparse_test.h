/*
 * sfparse
 *
 * Copyright (c) 2023 sfparse contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef SFPARSE_TEST_H
#define SFPARSE_TEST_H

#define MUNIT_ENABLE_ASSERT_ALIASES

#include "munit.h"

extern const MunitSuite sfparse_suite;

munit_void_test_decl(test_sfparse_parser_item_skip)
munit_void_test_decl(test_sfparse_parser_dict_skip)
munit_void_test_decl(test_sfparse_parser_list_skip)
munit_void_test_decl(test_sfparse_parser_byteseq)
munit_void_test_decl(test_sfparse_parser_boolean)
munit_void_test_decl(test_sfparse_parser_number)
munit_void_test_decl(test_sfparse_parser_date)
munit_void_test_decl(test_sfparse_parser_string)
munit_void_test_decl(test_sfparse_parser_token)
munit_void_test_decl(test_sfparse_parser_dispstring)
munit_void_test_decl(test_sfparse_parser_dictionary)
munit_void_test_decl(test_sfparse_parser_list)
munit_void_test_decl(test_sfparse_parser_list_list)
munit_void_test_decl(test_sfparse_parser_param_dict)
munit_void_test_decl(test_sfparse_parser_param_list)
munit_void_test_decl(test_sfparse_parser_param_list_list)
munit_void_test_decl(test_sfparse_parser_number_generated)
munit_void_test_decl(test_sfparse_parser_string_generated)
munit_void_test_decl(test_sfparse_parser_token_generated)
munit_void_test_decl(test_sfparse_parser_key_generated)
munit_void_test_decl(test_sfparse_parser_byteseq_generated)
munit_void_test_decl(test_sfparse_parser_large_generated)
munit_void_test_decl(test_sfparse_parser_examples)

#endif /* !defined(SFPARSE_TEST_H) */
