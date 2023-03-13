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

void test_sf_parser_item_skip(void);
void test_sf_parser_dict_skip(void);
void test_sf_parser_list_skip(void);
void test_sf_parser_byteseq(void);
void test_sf_parser_boolean(void);
void test_sf_parser_number(void);
void test_sf_parser_date(void);
void test_sf_parser_string(void);
void test_sf_parser_token(void);
void test_sf_parser_dictionary(void);
void test_sf_parser_list(void);
void test_sf_parser_list_list(void);
void test_sf_parser_param_dict(void);
void test_sf_parser_param_list(void);
void test_sf_parser_param_list_list(void);
void test_sf_parser_number_generated(void);
void test_sf_parser_string_generated(void);
void test_sf_parser_token_generated(void);
void test_sf_parser_key_generated(void);
void test_sf_parser_large_generated(void);
void test_sf_parser_examples(void);

#endif /* SFPARSE_TEST_H */
