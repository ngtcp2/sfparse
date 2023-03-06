/*
 * sfparse
 *
 * Copyright (c) 2023 sfparse contributors
 * Copyright (c) 2019 nghttp3 contributors
 * Copyright (c) 2016 ngtcp2 contributors
 * Copyright (c) 2012 nghttp2 contributors
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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
/* include test cases' include files here */
#include "sfparse_test.h"

static int init_suite1(void) { return 0; }

static int clean_suite1(void) { return 0; }

int main(void) {
  CU_pSuite pSuite = NULL;
  unsigned int num_tests_failed;

  /* initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry())
    return (int)CU_get_error();

  /* add a suite to the registry */
  pSuite = CU_add_suite("sfparse_TestSuite", init_suite1, clean_suite1);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* add the tests to the suite */
  if (!CU_add_test(pSuite, "sf_parser_item_skip", test_sf_parser_item_skip) ||
      !CU_add_test(pSuite, "sf_parser_dict_skip", test_sf_parser_dict_skip) ||
      !CU_add_test(pSuite, "sf_parser_list_skip", test_sf_parser_list_skip) ||
      !CU_add_test(pSuite, "sf_parser_byteseq", test_sf_parser_byteseq) ||
      !CU_add_test(pSuite, "sf_parser_boolean", test_sf_parser_boolean) ||
      !CU_add_test(pSuite, "sf_parser_number", test_sf_parser_number) ||
      !CU_add_test(pSuite, "sf_parser_string", test_sf_parser_string) ||
      !CU_add_test(pSuite, "sf_parser_token", test_sf_parser_token) ||
      !CU_add_test(pSuite, "sf_parser_dictionary", test_sf_parser_dictionary) ||
      !CU_add_test(pSuite, "sf_parser_list", test_sf_parser_list) ||
      !CU_add_test(pSuite, "sf_parser_list_list", test_sf_parser_list_list) ||
      !CU_add_test(pSuite, "sf_parser_param_dict", test_sf_parser_param_dict) ||
      !CU_add_test(pSuite, "sf_parser_param_list", test_sf_parser_param_list) ||
      !CU_add_test(pSuite, "sf_parser_param_list_list",
                   test_sf_parser_param_list_list) ||
      !CU_add_test(pSuite, "sf_parser_number_generated",
                   test_sf_parser_number_generated) ||
      !CU_add_test(pSuite, "sf_parser_string_generated",
                   test_sf_parser_string_generated) ||
      !CU_add_test(pSuite, "sf_parser_token_generated",
                   test_sf_parser_token_generated) ||
      !CU_add_test(pSuite, "sf_parser_key_generated",
                   test_sf_parser_key_generated) ||
      !CU_add_test(pSuite, "sf_parser_large_generated",
                   test_sf_parser_large_generated) ||
      !CU_add_test(pSuite, "sf_parser_examples", test_sf_parser_examples)) {
    CU_cleanup_registry();
    return (int)CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  num_tests_failed = CU_get_number_of_tests_failed();
  CU_cleanup_registry();
  if (CU_get_error() == CUE_SUCCESS) {
    return (int)num_tests_failed;
  } else {
    printf("CUnit Error: %s\n", CU_get_error_msg());
    return (int)CU_get_error();
  }
}
