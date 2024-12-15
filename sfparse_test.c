/*
 * sfparse
 *
 * Copyright (c) 2023 sfparse contributors
 * Copyright (c) 2023 nghttp3 contributors
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
#include "sfparse_test.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sfparse.h"

static const MunitTest tests[] = {
  munit_void_test(test_sfparse_parser_item_skip),
  munit_void_test(test_sfparse_parser_dict_skip),
  munit_void_test(test_sfparse_parser_list_skip),
  munit_void_test(test_sfparse_parser_byteseq),
  munit_void_test(test_sfparse_parser_boolean),
  munit_void_test(test_sfparse_parser_number),
  munit_void_test(test_sfparse_parser_date),
  munit_void_test(test_sfparse_parser_string),
  munit_void_test(test_sfparse_parser_token),
  munit_void_test(test_sfparse_parser_dispstring),
  munit_void_test(test_sfparse_parser_dictionary),
  munit_void_test(test_sfparse_parser_list),
  munit_void_test(test_sfparse_parser_list_list),
  munit_void_test(test_sfparse_parser_param_dict),
  munit_void_test(test_sfparse_parser_param_list),
  munit_void_test(test_sfparse_parser_param_list_list),
  munit_void_test(test_sfparse_parser_number_generated),
  munit_void_test(test_sfparse_parser_string_generated),
  munit_void_test(test_sfparse_parser_token_generated),
  munit_void_test(test_sfparse_parser_key_generated),
  munit_void_test(test_sfparse_parser_byteseq_generated),
  munit_void_test(test_sfparse_parser_large_generated),
  munit_void_test(test_sfparse_parser_examples),
  munit_test_end(),
};

const MunitSuite sfparse_suite = {
  "/sfparse", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

#define sfparse_parser_bytes_init(SFP, S)                                      \
  {                                                                            \
    uint8_t *input_buffer = malloc(sizeof(S) - 1);                             \
    memcpy(input_buffer, (S), sizeof(S) - 1);                                  \
    sfparse_parser_init((SFP), input_buffer, sizeof(S) - 1);

#define sfparse_parser_bytes_len_init(SFP, DATA, DATALEN)                      \
  {                                                                            \
    uint8_t *input_buffer = malloc((DATALEN));                                 \
    memcpy(input_buffer, (DATA), (DATALEN));                                   \
    sfparse_parser_init((SFP), input_buffer, (DATALEN));

#define sfparse_parser_bytes_free()                                            \
  free(input_buffer);                                                          \
  }

static int str_sfparse_vec_eq(const char *s, const sfparse_vec *v) {
  return strlen(s) == v->len &&
         (v->len == 0 || 0 == memcmp(s, v->base, v->len));
}

#define assert_str_sfparse_vec_eq(S, V)                                        \
  do {                                                                         \
    assert_size(strlen(S), ==, (V)->len);                                      \
    if ((V)->len) {                                                            \
      assert_memory_equal((V)->len, (S), (V)->base);                           \
    }                                                                          \
  } while (0);

static int is_first_token_char(const uint8_t c) {
  return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || c == '*';
}

static int is_token_char(const uint8_t c) {
  return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') ||
         ('0' <= c && c <= '9') || c == '!' || c == '#' || c == '$' ||
         c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
         c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' ||
         c == '~' || c == ':' || c == '/';
}

static int is_first_key_char(const uint8_t c) {
  return ('a' <= c && c <= 'z') || c == '*';
}

static int is_key_char(const uint8_t c) {
  return ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '_' ||
         c == '-' || c == '.' || c == '*';
}

void test_sfparse_parser_item_skip(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  {
    /* skip empty parameter */
    sfparse_parser_bytes_init(&sfp, "a");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sfparse_parser_bytes_init(&sfp, "a;f=1000000009;g=1000000007");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip boolean parameter */
    sfparse_parser_bytes_init(&sfp, "a;f");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with empty parameter */
    sfparse_parser_bytes_init(&sfp, "(a)");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with non-empty parameter */
    sfparse_parser_bytes_init(&sfp, "(a);f=1000000009;g=1000000007");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sfparse_parser_bytes_init(&sfp, "(a);f");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sfparse_parser_bytes_init(&sfp, "(a);f");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("f", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sfparse_parser_bytes_init(&sfp, "(1;foo=100 2;bar)");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));
    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_dict_skip(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  {
    /* skip empty parameter */
    sfparse_parser_bytes_init(&sfp, "a=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sfparse_parser_bytes_init(&sfp, "a=3;f=999;g=1.23");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip boolean parameter */
    sfparse_parser_bytes_init(&sfp, "a=3;f");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list */
    sfparse_parser_bytes_init(&sfp, "a=(1 2 3) , b=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with parameter */
    sfparse_parser_bytes_init(&sfp, "a=(1 2 3);f=a;g=b , b=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sfparse_parser_bytes_init(&sfp, "a=(1 2 3);f;g , b=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sfparse_parser_bytes_init(&sfp, "a=(1 2 3);f;g , b=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("f", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("g", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sfparse_parser_bytes_init(&sfp, "a=(1;foo=100 2;bar)");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_list_skip(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  {
    /* skip empty parameter */
    sfparse_parser_bytes_init(&sfp, "a");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sfparse_parser_bytes_init(&sfp, "a;fff=1;ggg=9");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list */
    sfparse_parser_bytes_init(&sfp, "(1 2 3) , 333");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(333, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with parameter */
    sfparse_parser_bytes_init(&sfp, "(1 2 3);f=a;g=b , 333");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(333, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sfparse_parser_bytes_init(&sfp, "(1 2 3);f;g , 333");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(333, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sfparse_parser_bytes_init(&sfp, "(1 2 3);f;g , 333");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("f", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("g", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(333, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sfparse_parser_bytes_init(&sfp, "(1;foo=100 2;bar)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_byteseq(void) {
  sfparse_parser sfp;
  sfparse_value val;
  sfparse_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/binary.json */

  {
    /* basic binary */
    sfparse_parser_bytes_init(&sfp, ":aGVsbG8=:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("aGVsbG8=", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("hello", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* empty binary */
    sfparse_parser_bytes_init(&sfp, "::");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* bad paddding */
    sfparse_parser_bytes_init(&sfp, ":aGVsbG8:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("aGVsbG8", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("hello", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* bad end delimiter */
    sfparse_parser_bytes_init(&sfp, ":aGVsbG8=");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace */
    sfparse_parser_bytes_init(&sfp, ":aGVsb G8=:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra chars */
    sfparse_parser_bytes_init(&sfp, ":aGVsbG!8=:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* suffix chars */
    sfparse_parser_bytes_init(&sfp, ":aGVsbG8=!:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* non-zero pad bits */
    sfparse_parser_bytes_init(&sfp, ":iZ==:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("iZ==", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\x89", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* non-ASCII binary */
    sfparse_parser_bytes_init(&sfp, ":/+Ah:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("/+Ah", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\xff\xe0!", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* base64url binary */
    sfparse_parser_bytes_init(&sfp, ":_-Ah:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* missing closing DQUOTE */
    sfparse_parser_bytes_init(&sfp, "z,:1jk=");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("z", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Just ':' */
    sfparse_parser_bytes_init(&sfp, ":");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Just single '=' */
    sfparse_parser_bytes_init(&sfp, ":=:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Two '=' */
    sfparse_parser_bytes_init(&sfp, ":==:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Three '=' */
    sfparse_parser_bytes_init(&sfp, ":===:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Four '=' */
    sfparse_parser_bytes_init(&sfp, ":====:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Single letter never be a base64 encoded string */
    sfparse_parser_bytes_init(&sfp, ":K:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Omitting all padding and non-zero pad bits */
    sfparse_parser_bytes_init(&sfp, ":K7:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("K7", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\x2b", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Omitting a single padding and non-zero pad bits */
    sfparse_parser_bytes_init(&sfp, ":K7=:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("K7=", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\x2b", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Omitting a padding and non-zero pad bits */
    sfparse_parser_bytes_init(&sfp, ":K73:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("K73", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\x2b\xbd", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Not omitting a padding but non-zero pad bits */
    sfparse_parser_bytes_init(&sfp, ":K73=:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("K73=", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\x2b\xbd", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Padding in the middle of encoded string */
    sfparse_parser_bytes_init(&sfp, ":ab=a:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* long binary with extra chars */
    sfparse_parser_bytes_init(
      &sfp, ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg!==:");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_boolean(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/boolean.json */

  {
    /* basic true boolean */
    sfparse_parser_bytes_init(&sfp, "?1");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* basic false boolean */
    sfparse_parser_bytes_init(&sfp, "?0");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_false(val.boolean);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* unknown boolean */
    sfparse_parser_bytes_init(&sfp, "?Q");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace boolean */
    sfparse_parser_bytes_init(&sfp, "? 1");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* negative zero boolean */
    sfparse_parser_bytes_init(&sfp, "?-0");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* T boolean */
    sfparse_parser_bytes_init(&sfp, "?T");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* F boolean */
    sfparse_parser_bytes_init(&sfp, "?F");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* t boolean */
    sfparse_parser_bytes_init(&sfp, "?t");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* f boolean */
    sfparse_parser_bytes_init(&sfp, "?f");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* spelled-out True boolean */
    sfparse_parser_bytes_init(&sfp, "?True");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* spelled-out False boolean */
    sfparse_parser_bytes_init(&sfp, "?False");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '?' */
    sfparse_parser_bytes_init(&sfp, "?");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_number(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/number.json */

  {
    /* basic integer */
    sfparse_parser_bytes_init(&sfp, "42");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* zero integer */
    sfparse_parser_bytes_init(&sfp, "0");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(0, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* negative zero */
    sfparse_parser_bytes_init(&sfp, "-0");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(0, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* double negative zero */
    sfparse_parser_bytes_init(&sfp, "--0");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* negative integer */
    sfparse_parser_bytes_init(&sfp, "-42");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(-42, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* leading 0 integer */
    sfparse_parser_bytes_init(&sfp, "042");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* leading 0 negative integer */
    sfparse_parser_bytes_init(&sfp, "-042");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(-42, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* leading 0 zero */
    sfparse_parser_bytes_init(&sfp, "00");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(0, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* comma */
    sfparse_parser_bytes_init(&sfp, "2,3");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);
    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* negative non-DIGIT first character */
    sfparse_parser_bytes_init(&sfp, "-a23");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* sign out of place */
    sfparse_parser_bytes_init(&sfp, "4-2");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(4, ==, val.integer);
    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after sign */
    sfparse_parser_bytes_init(&sfp, "- 42");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* long integer */
    sfparse_parser_bytes_init(&sfp, "123456789012345");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(123456789012345, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* long negative integer */
    sfparse_parser_bytes_init(&sfp, "-123456789012345");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(-123456789012345, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* too long integer */
    sfparse_parser_bytes_init(&sfp, "1234567890123456");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* negative too long integer */
    sfparse_parser_bytes_init(&sfp, "-1234567890123456");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* simple decimal */
    sfparse_parser_bytes_init(&sfp, "1.23");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(123, ==, val.decimal.numer);
    assert_int64(100, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* negative decimal */
    sfparse_parser_bytes_init(&sfp, "-1.23");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(-123, ==, val.decimal.numer);
    assert_int64(100, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* decimal, whitespace after decimal */
    sfparse_parser_bytes_init(&sfp, "1. 23");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* decimal, whitespace before decimal */
    sfparse_parser_bytes_init(&sfp, "1 .23");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);
    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* negative decimal, whitespace after sign */
    sfparse_parser_bytes_init(&sfp, "- 1.23");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* tricky precision decimal */
    sfparse_parser_bytes_init(&sfp, "123456789012.1");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(1234567890121, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* double decimal decimal */
    sfparse_parser_bytes_init(&sfp, "1.5.4");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(15, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* adjacent double decimal decimal */
    sfparse_parser_bytes_init(&sfp, "1..4");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* decimal with three fractional digits */
    sfparse_parser_bytes_init(&sfp, "1.123");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(1123, ==, val.decimal.numer);
    assert_int64(1000, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* negative decimal with three fractional digits */
    sfparse_parser_bytes_init(&sfp, "-1.123");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(-1123, ==, val.decimal.numer);
    assert_int64(1000, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* decimal with four fractional digits */
    sfparse_parser_bytes_init(&sfp, "1.1234");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* negative decimal with four fractional digits */
    sfparse_parser_bytes_init(&sfp, "-1.1234");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* decimal with thirteen integer digits */
    sfparse_parser_bytes_init(&sfp, "1234567890123.0");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* negative decimal with thirteen integer digits */
    sfparse_parser_bytes_init(&sfp, "-1234567890123.0");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* No digits */
    sfparse_parser_bytes_init(&sfp, "-a");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* No digits before '.' */
    sfparse_parser_bytes_init(&sfp, "-.1");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_date(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/date.json */

  {
    /* date - 1970-01-01 00:00:00 */
    sfparse_parser_bytes_init(&sfp, "@0");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DATE, ==, val.type);
    assert_int64(0, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* date - 2022-08-04 01:57:13 */
    sfparse_parser_bytes_init(&sfp, "@1659578233");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DATE, ==, val.type);
    assert_int64(1659578233, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* date - 1917-05-30 22:02:47 */
    sfparse_parser_bytes_init(&sfp, "@-1659578233");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DATE, ==, val.type);
    assert_int64(-1659578233, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* date - 2^31 */
    sfparse_parser_bytes_init(&sfp, "@2147483648");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DATE, ==, val.type);
    assert_int64(2147483648, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* date - 2^32 */
    sfparse_parser_bytes_init(&sfp, "@4294967296");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DATE, ==, val.type);
    assert_int64(4294967296, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* date - decimal */
    sfparse_parser_bytes_init(&sfp, "@1659578233.12");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '@' */
    sfparse_parser_bytes_init(&sfp, "@");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_string(void) {
  sfparse_parser sfp;
  sfparse_value val;
  sfparse_vec unescaped;
  uint8_t buf[256];

  /* https://github.com/httpwg/structured-field-tests/blob/main/string.json */

  {
    /* basic string */
    sfparse_parser_bytes_init(&sfp, "\"foo bar\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo bar", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* empty string */
    sfparse_parser_bytes_init(&sfp, "\"\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* long string */
    sfparse_parser_bytes_init(
      &sfp,
      "\"foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo \"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq(
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo ",
      &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace string */
    sfparse_parser_bytes_init(&sfp, "\"   \"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("   ", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* non-ascii string */
    sfparse_parser_bytes_init(&sfp, "\"füü\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* tab in string */
    sfparse_parser_bytes_init(&sfp, "\"\\t\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* newline in string */
    sfparse_parser_bytes_init(&sfp, "\" \\n \"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single quoted string */
    sfparse_parser_bytes_init(&sfp, "'foo'");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* unbalanced string */
    sfparse_parser_bytes_init(&sfp, "\"foo");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* string quoting */
    sfparse_parser_bytes_init(&sfp, "\"foo \\\"bar\\\" \\\\ baz\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo \\\"bar\\\" \\\\ baz", &val.vec);
    assert_true(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);

    unescaped.base = buf;
    sfparse_unescape(&unescaped, &val.vec);

    assert_str_sfparse_vec_eq("foo \"bar\" \\ baz", &unescaped);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* bad string quoting */
    sfparse_parser_bytes_init(&sfp, "\"foo \\,\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* ending string quote */
    sfparse_parser_bytes_init(&sfp, "\"foo \\\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* abruptly ending string quote */
    sfparse_parser_bytes_init(&sfp, "\"foo \\");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '"' */
    sfparse_parser_bytes_init(&sfp, "\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* long string with invalid char */
    sfparse_parser_bytes_init(
      &sfp,
      "\"foo foo foo foo foo foo foo foo \x7f foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
      "foo foo foo foo foo foo foo foo foo foo foo foo foo foo \"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_token(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/token.json */

  {
    /* basic token - item */
    sfparse_parser_bytes_init(&sfp, "a_b-c.d3:f%00/*");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a_b-c.d3:f%00/*", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* token with capitals - item */
    sfparse_parser_bytes_init(&sfp, "fooBar");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("fooBar", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* token starting with capitals - item */
    sfparse_parser_bytes_init(&sfp, "FooBar");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("FooBar", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* basic token - list */
    sfparse_parser_bytes_init(&sfp, "a_b-c3/*");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a_b-c3/*", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* token with capitals - list */
    sfparse_parser_bytes_init(&sfp, "fooBar");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("fooBar", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* token starting with capitals - list */
    sfparse_parser_bytes_init(&sfp, "FooBar");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("FooBar", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_dispstring(void) {
  sfparse_parser sfp;
  sfparse_value val;
  sfparse_vec decoded;
  uint8_t buf[128];

  /* https://github.com/httpwg/structured-field-tests/blob/main/display-string.json
   */

  {
    /* basic display string (ascii content) */
    sfparse_parser_bytes_init(&sfp, "%\"foo bar\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo bar", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("foo bar", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* all printable ascii */
    sfparse_parser_bytes_init(&sfp,
                              "%\" "
                              "!%22#$%25&'()*+,-./"
                              "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
                              "^_`abcdefghijklmnopqrstuvwxyz{|}~\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq(" !%22#$%25&'()*+,-./"
                              "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
                              "^_`abcdefghijklmnopqrstuvwxyz{|}~",
                              &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_true(
      str_sfparse_vec_eq(" !\"#$%&'()*+,-./"
                         "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                         "abcdefghijklmnopqrstuvwxyz{|}~",
                         &decoded));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* non-ascii display string (uppercase escaping) */
    sfparse_parser_bytes_init(&sfp, "%\"f%C3%BC%C3%BC\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* non-ascii display string (lowercase escaping) */
    sfparse_parser_bytes_init(&sfp, "%\"f%c3%bc%c3%bc\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("f%c3%bc%c3%bc", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("füü", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* tab in display string */
    sfparse_parser_bytes_init(&sfp, "%\"\t\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* newline in display string */
    sfparse_parser_bytes_init(&sfp, "%\"\n\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single quoted display string */
    sfparse_parser_bytes_init(&sfp, "%'foo'");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* unquoted display string */
    sfparse_parser_bytes_init(&sfp, "%foo");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* display string missing initial quote */
    sfparse_parser_bytes_init(&sfp, "%foo\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* unbalanced display string */
    sfparse_parser_bytes_init(&sfp, "%\"foo");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* display string quoting */
    sfparse_parser_bytes_init(&sfp, "%\"foo %22bar%22 \\ baz\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo %22bar%22 \\ baz", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("foo \"bar\" \\ baz", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string escaping */
    sfparse_parser_bytes_init(&sfp, "%\"foo %a");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 2-byte seq) */
    sfparse_parser_bytes_init(&sfp, "%\"%c3%28\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid sequence id) */
    sfparse_parser_bytes_init(&sfp, "%\"%a0%a1\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid hex) */
    sfparse_parser_bytes_init(&sfp, "%\"%g0%1w\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 3-byte seq) */
    sfparse_parser_bytes_init(&sfp, "%\"%e2%28%a1\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 4-byte seq) */
    sfparse_parser_bytes_init(&sfp, "%\"%f0%28%8c%28\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* BOM in display string */
    sfparse_parser_bytes_init(&sfp, "%\"BOM: %ef%bb%bf\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("BOM: %ef%bb%bf", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("BOM: \xef\xbb\xbf", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* base UTF-8 string */
    sfparse_parser_bytes_init(
      &sfp,
      "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq(
      "%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c",
      &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1"
                              "\xe3\x81\xaf\xe4\xb8\x96\xe7\x95\x8c",
                              &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* truncated UTF-8 string */
    sfparse_parser_bytes_init(&sfp, "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81"
                                    "%a1%e3%81%af%e4%b8%96%e7%95\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Just '%' */
    sfparse_parser_bytes_init(&sfp, "%");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* just '%"' */
    sfparse_parser_bytes_init(&sfp, "%\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty dispstring */
    sfparse_parser_bytes_init(&sfp, "%\"\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* base UTF-8 string without closing DQUOTE */
    sfparse_parser_bytes_init(
      &sfp,
      "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* illegal character */
    sfparse_parser_bytes_init(&sfp, "%\""
                                    "\x00"
                                    "\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad percent encoding (first half) */
    sfparse_parser_bytes_init(&sfp, "%\"%qa\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad percent encoding (second half) */
    sfparse_parser_bytes_init(&sfp, "%\"%aq\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad percent encoding (missing 2 bytes) */
    sfparse_parser_bytes_init(&sfp, "%\"%\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad percent encoding (missing 2nd byte) */
    sfparse_parser_bytes_init(&sfp, "%\"%a\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* ASCII string */
    sfparse_parser_bytes_init(&sfp, "%\"hello world\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_str_sfparse_vec_eq("hello world", &val.vec);

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("hello world", &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* ASCII + percent-encoded UTF-8 byte sequence */
    sfparse_parser_bytes_init(
      &sfp, "%\"This is intended for display to %c3%bcsers.\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DISPSTRING, ==, val.type);
    assert_true(str_sfparse_vec_eq(
      "This is intended for display to %c3%bcsers.", &val.vec));

    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("This is intended for display to "
                              "\xc3\xbc"
                              "sers.",
                              &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* overlong 2 byte sequence */
    sfparse_parser_bytes_init(&sfp, "%\"%c0%af\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* Uppercase percent-encoded string is invalid */
    sfparse_parser_bytes_init(
      &sfp, "%\"This is intended for display to %C3%BCsers.\"");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_dictionary(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  sfparse_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/dictionary.json
   */

  {
    /* basic dictionary */
    sfparse_parser_bytes_init(&sfp, "en=\"Applepie\", da=:w4ZibGV0w6ZydGUK:");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("en", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("Applepie", &val.vec);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("da", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("w4ZibGV0w6ZydGUK", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\xc3\x86"
                              "blet\xc3\xa6"
                              "rte\n",
                              &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* empty dictionary */
    sfparse_parser_init(&sfp, (const uint8_t *)"", 0);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));
  }

  {
    /* single item dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* list item dictionary */
    sfparse_parser_bytes_init(&sfp, "a=(1 2)");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single list item dictionary */
    sfparse_parser_bytes_init(&sfp, "a=(1)");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty list item dictionary */
    sfparse_parser_bytes_init(&sfp, "a=()");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no whitespace dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1,b=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1 ,  b=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* tab separated dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1\t,\tb=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* leading whitespace dictionary */
    sfparse_parser_bytes_init(&sfp, "     a=1 ,  b=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace before = dictionary */
    sfparse_parser_bytes_init(&sfp, "a =1, b=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after = dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b= 2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  /* two lines dictionary */
  /* sfparse_parser does not support merging 2 lines */

  {
    /* missing value dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b, c=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* all missing value dictionary */
    sfparse_parser_bytes_init(&sfp, "a, b, c");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* start missing value dictionary */
    sfparse_parser_bytes_init(&sfp, "a, b=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* end missing value dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* missing value with params dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b;foo=9, c=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foo", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(9, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* explicit true value with params dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b=?1;foo=9, c=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foo", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(9, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* trailing comma dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1, b=2,");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty item dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1,,b=2,");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* duplicate key dictionary */
    /* sfparse_parser does no effort to find duplicates. */
    sfparse_parser_bytes_init(&sfp, "a=1,b=2,a=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* numeric key dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1,1b=2,a=1");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* uppercase key dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1,B=2,a=1");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* bad key dictionary */
    sfparse_parser_bytes_init(&sfp, "a=1,b!=2,a=1");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Empty value */
    sfparse_parser_bytes_init(&sfp, "a=");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_list(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/list.json */

  {
    /* basic list */
    sfparse_parser_bytes_init(&sfp, "1, 42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty list */
    sfparse_parser_init(&sfp, (const uint8_t *)"", 0);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));
  }

  {
    /* leading SP list */
    sfparse_parser_bytes_init(&sfp, "  42, 43");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(43, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single item list */
    sfparse_parser_bytes_init(&sfp, "42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no whitespace list */
    sfparse_parser_bytes_init(&sfp, "1,42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace list */
    sfparse_parser_bytes_init(&sfp, "1 , 42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* tab separated list */
    sfparse_parser_bytes_init(&sfp, "1\t,\t42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* two line list */
  /* sfparse_parser does not support merging 2 lines */

  {
    /* trailing comma list */
    sfparse_parser_bytes_init(&sfp, "1, 42,");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty item list */
    sfparse_parser_bytes_init(&sfp, "1,,42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* empty item list (multiple field lines) */
  /* sfparse_parser does not support merging 2 lines */
}

void test_sfparse_parser_list_list(void) {
  sfparse_parser sfp;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/listlist.json */

  {
    /* basic list of lists */
    sfparse_parser_bytes_init(&sfp, "(1 2), (42 43)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(43, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single item list of lists */
    sfparse_parser_bytes_init(&sfp, "(42)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty item list of lists */
    sfparse_parser_bytes_init(&sfp, "()");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty middle item list of lists */
    sfparse_parser_bytes_init(&sfp, "(1),(),(42)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace list of lists */
    sfparse_parser_bytes_init(&sfp, "(  1  42  )");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* wrong whitespace list of lists */
    sfparse_parser_bytes_init(&sfp, "(1\t 42)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no trailing parenthesis list of lists */
    sfparse_parser_bytes_init(&sfp, "(1 42");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no trailing parenthesis middle list of lists */
    sfparse_parser_bytes_init(&sfp, "(1 2, (42 43)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no spaces in inner-list */
    sfparse_parser_bytes_init(&sfp, "(abc\"def\"?0123*dXZ3*xyz)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no closing parenthesis */
    sfparse_parser_bytes_init(&sfp, "(");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just ')' */
    sfparse_parser_bytes_init(&sfp, ")");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_param_dict(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-dict.json
   */

  {
    /* basic parameterised dict */
    sfparse_parser_bytes_init(&sfp,
                              "abc=123;a=1;b=2, def=456, ghi=789;q=9;r=\"+w\"");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("abc", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(123, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("def", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(456, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("ghi", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(789, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(9, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("r", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("+w", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single item parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b; q=1.0");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* list item parameterised dictionary */
    sfparse_parser_bytes_init(&sfp, "a=(1 2); q=1.0");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* missing parameter value parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=3;c;d=5");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("d", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* terminal missing parameter value parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=3;c=5;d");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("d", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no whitespace parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b;c=1,d=e;f=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("d", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("e", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("f", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace before = parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b;q =0.5");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after = parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b;q= 0.5");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_param(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace before ; parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b ;q=0.5");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after ; parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b; q=0.5");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(5, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace parameterised dict */
    sfparse_parser_bytes_init(&sfp, "a=b;  c=1  ,  d=e; f=2; g=3");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("d", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("e", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("f", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("g", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  /* two lines parameterised list */
  /* sfparse_parser does not support merging 2 lines */

  {
    /* trailing comma parameterised list */
    sfparse_parser_bytes_init(&sfp, "a=b; q=1.0,");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty item parameterised list */
    sfparse_parser_bytes_init(&sfp, "a=b; q=1.0,,c=d");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sfparse_parser_bytes_init(&sfp, "a=b;c=");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("b", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_param(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_param_list(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-list.json
   */

  {
    /* basic parameterised list */
    sfparse_parser_bytes_init(&sfp,
                              "abc_123;a=1;b=2; cdef_456, ghi;q=9;r=\"+w\"");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc_123", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("cdef_456", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("ghi", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(9, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("r", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("+w", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* single item parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html;q=1.0");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* missing parameter value parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html;a;q=1.0");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* missing terminal parameter value parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html;q=1.0;a");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(10, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* no whitespace parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html,text/plain;q=0.5");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(5, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace before = parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html, text/plain;q =0.5");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after = parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html, text/plain;q= 0.5");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_param(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace before ; parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html, text/plain ;q=0.5");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* whitespace after ; parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html, text/plain; q=0.5");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(5, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* extra whitespace parameterised list */
    sfparse_parser_bytes_init(
      &sfp, "text/html  ,  text/plain;  q=0.5;  charset=utf-8");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(5, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("charset", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("utf-8", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* two lines parameterised list */
  /* sfparse_parser does not support merging 2 lines */

  {
    /* trailing comma parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html,text/plain;q=0.5,");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/plain", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(5, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* empty item parameterised list */
    sfparse_parser_bytes_init(&sfp, "text/html,,text/plain;q=0.5,");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("text/html", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sfparse_parser_bytes_init(&sfp, "a;b=");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_param(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_param_list_list(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-listlist.json
   */

  {
    /* parameterised inner list */
    sfparse_parser_bytes_init(&sfp, "(abc_123);a=1;b=2, cdef_456");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc_123", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("cdef_456", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* parameterised inner list item */
    sfparse_parser_bytes_init(&sfp, "(abc_123;a=1;b=2;cdef_456)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc_123", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("cdef_456", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* parameterised inner list with parameterised item */
    sfparse_parser_bytes_init(&sfp, "(abc_123;a=1;b=2);cdef_456");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc_123", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("cdef_456", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sfparse_parser_bytes_init(&sfp, "(a;b= 1)");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("a", &val.vec);

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_param(&sfp, &key, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_number_generated(void) {
  sfparse_parser sfp;
  sfparse_value val;
  size_t len, i, j;
  size_t flen;
  const char digits[] = {'0', '1', '9'};
  const char d_digits[] = {'0', '1', '1', '9'};
  const char df_digits[] = {'1', '0', '1', '9'};
  uint8_t buf[64];
  int64_t integer;
  int64_t denom;

  for (len = 1; len <= 15; ++len) {
    for (i = 0; i < sizeof(digits) / sizeof(digits[0]); ++i) {
      memset(buf, digits[i], len);
      buf[len] = '\0';

      integer = strtoll((char *)buf, NULL, 10);

      sfparse_parser_bytes_len_init(&sfp, buf, len);

      assert_int(0, ==, sfparse_parser_item(&sfp, &val));
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(integer, ==, val.integer);

      sfparse_parser_bytes_free();
    }
  }

  for (len = 1; len <= 12; ++len) {
    for (flen = 1; flen <= 3; ++flen) {
      for (i = 0; i < sizeof(d_digits) / sizeof(d_digits[0]); ++i) {
        memset(buf, d_digits[i], len);
        memset(buf + len, df_digits[i], flen);
        buf[len + flen] = '\0';

        integer = strtoll((char *)buf, NULL, 10);

        buf[len] = '.';
        memset(buf + len + 1, df_digits[i], flen);
        buf[len + 1 + flen] = '\0';

        denom = 1;
        for (j = 0; j < flen; ++j) {
          denom *= 10;
        }

        sfparse_parser_bytes_len_init(&sfp, buf, len + 1 + flen);

        assert_int(0, ==, sfparse_parser_item(&sfp, &val));
        assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
        assert_int64(integer, ==, val.decimal.numer);
        assert_int64(denom, ==, val.decimal.denom);
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

        sfparse_parser_bytes_free();
      }
    }
  }

  {
    /* too many digit 0 decimal */
    sfparse_parser_bytes_init(&sfp, "000000000000000.0");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* too many fractional digits 0 decimal */
    sfparse_parser_bytes_init(&sfp, "000000000000.0000");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* too many digit 9 decimal */
    sfparse_parser_bytes_init(&sfp, "999999999999999.9");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }

  {
    /* too many fractional digits 9 decimal */
    sfparse_parser_bytes_init(&sfp, "999999999999.9999");

    assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, &val));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_string_generated(void) {
  sfparse_parser sfp;
  sfparse_value val;
  size_t i;
  uint8_t buf[64];
  int rv;

  /* 0x?? in string */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = '"';
    buf[1] = ' ';
    buf[2] = (uint8_t)i;
    buf[3] = ' ';
    buf[4] = '"';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_item(&sfp, &val);

    if (i == 0x20 || i == 0x21 || (0x23 <= i && i <= 0x5b) ||
        (0x5d <= i && i <= 0x7e) || i == 0x22) {
      assert_int(0, ==, rv);

      rv = sfparse_parser_item(&sfp, NULL);

      if (i == 0x22) {
        assert_int(SFPARSE_ERR_PARSE, ==, rv);
      } else {
        assert_int(SFPARSE_ERR_EOF, ==, rv);
      }
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }

  /* Escaped 0x?? in string */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = '"';
    buf[1] = '\\';
    buf[2] = (uint8_t)i;
    buf[3] = '"';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_item(&sfp, &val);

    if (i == '\\' || i == '"') {
      assert_int(0, ==, rv);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_token_generated(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  size_t i;
  uint8_t buf[64];
  int rv;

  /* 0x?? in token */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = 'a';
    buf[1] = (uint8_t)i;
    buf[2] = 'a';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));

    if (is_token_char((uint8_t)i)) {
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_size(3, ==, val.vec.len);
      assert_memory_equal(3, buf, val.vec.base);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));
    } else {
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("a", &val.vec);

      if (i == ';') {
        assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
        assert_str_sfparse_vec_eq("a", &key);
        assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
        assert_true(val.boolean);
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, &key, &val));
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, &val));
      } else {
        assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));
      }
    }

    sfparse_parser_bytes_free();
  }

  /* 0x?? starting a token */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = 'a';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_item(&sfp, &val);

    if (is_first_token_char((uint8_t)i)) {
      assert_int(0, ==, rv);
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_size(2, ==, val.vec.len);
      assert_memory_equal(2, buf, val.vec.base);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));
    } else if (i == ' ') {
      assert_int(0, ==, rv);
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("a", &val.vec);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));
    } else if ('0' <= i && i <= '9') {
      assert_int(0, ==, rv);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64((int64_t)(i - '0'), ==, val.integer);
      assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_item(&sfp, NULL));
    } else if (i == '(') {
      assert_int(0, ==, rv);
      assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);
      assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("a", &val.vec);
      assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_inner_list(&sfp, NULL));
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_key_generated(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  size_t i;
  uint8_t buf[64];
  int rv;
  int len;

  /* 0x?? as a single-character dictionary key */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = '=';
    buf[2] = '1';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_dict(&sfp, &key, &val);

    if (('a' <= i && i <= 'z') || i == '*') {
      assert_int(0, ==, rv);
      assert_size(1, ==, key.len);
      assert_uint8((uint8_t)i, ==, key.base[0]);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }

  /* 0x?? in dictionary key */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = 'a';
    buf[1] = (uint8_t)i;
    buf[2] = 'a';
    buf[3] = '=';
    buf[4] = '1';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_dict(&sfp, &key, &val);

    if (is_key_char((uint8_t)i)) {
      assert_int(0, ==, rv);
      assert_size(3, ==, key.len);
      assert_memory_equal(3, buf, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
    } else if (i == '=') {
      assert_int(0, ==, rv);
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("a", &val.vec);
      assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_dict(&sfp, NULL, NULL));
    } else {
      assert_int(0, ==, rv);
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
      assert_true(val.boolean);

      if (i == ',') {
        assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
        assert_str_sfparse_vec_eq("a", &key);
        assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
        assert_int64(1, ==, val.integer);
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
      } else if (i == ';') {
        assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
        assert_str_sfparse_vec_eq("a", &key);
        assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
        assert_int64(1, ==, val.integer);
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
      } else {
        assert_int(SFPARSE_ERR_PARSE, ==,
                   sfparse_parser_dict(&sfp, NULL, NULL));
      }
    }

    sfparse_parser_bytes_free();
  }

  /* 0x?? starting a dictionary key */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = 'a';
    buf[2] = '=';
    buf[3] = '1';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_dict(&sfp, &key, &val);

    if (is_first_key_char((uint8_t)i)) {
      assert_int(0, ==, rv);
      assert_size(2, ==, key.len);
      assert_memory_equal(2, buf, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
    } else if (i == ' ') {
      assert_int(0, ==, rv);
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }

  /* 0x?? in parameterised list key */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    len = snprintf((char *)buf, sizeof(buf), "foo; a%ca=1", (char)i);
    buf[len] = ' ';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));

    if (is_key_char((uint8_t)i)) {
      assert_size(3, ==, key.len);
      assert_memory_equal(3, buf + 5, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));
    } else if (i == '=') {
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("a", &val.vec);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
      assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, NULL));
    } else {
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
      assert_true(val.boolean);

      if (i == ';') {
        assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
        assert_str_sfparse_vec_eq("a", &key);
        assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
        assert_int64(1, ==, val.integer);
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));
      } else {
        assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

        rv = sfparse_parser_list(&sfp, &val);

        if (i == ',') {
          assert_int(0, ==, rv);
          assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
          assert_str_sfparse_vec_eq("a", &val.vec);
          assert_int(SFPARSE_ERR_PARSE, ==, sfparse_parser_list(&sfp, NULL));
        } else {
          assert_int(SFPARSE_ERR_PARSE, ==, rv);
        }
      }
    }

    sfparse_parser_bytes_free();
  }

  /* 0x?? starting a parameterised list key */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    len = snprintf((char *)buf, sizeof(buf), "foo; %ca=1", (char)i);
    buf[len] = ' ';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    rv = sfparse_parser_param(&sfp, &key, &val);

    if (is_first_key_char((uint8_t)i)) {
      assert_int(0, ==, rv);
      assert_size(2, ==, key.len);
      assert_memory_equal(2, buf + 5, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));
    } else if (i == ' ') {
      assert_int(0, ==, rv);
      assert_str_sfparse_vec_eq("a", &key);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_byteseq_generated(void) {
  sfparse_parser sfp;
  sfparse_value val;
  size_t i;
  uint8_t buf[64];
  int rv;

  /* 0x?? in byteseq */
  memset(buf, ' ', sizeof(buf));

  for (i = 0; i < 256; ++i) {
    buf[0] = ':';
    buf[1] = '/';
    buf[2] = (uint8_t)i;
    buf[3] = 'A';
    buf[4] = 'h';
    buf[5] = ':';

    sfparse_parser_bytes_len_init(&sfp, buf, sizeof(buf));

    rv = sfparse_parser_item(&sfp, &val);

    if (i == '+' || i == '/' || ('0' <= i && i <= '9') ||
        ('A' <= i && i <= 'Z') || ('a' <= i && i <= 'z')) {
      assert_int(0, ==, rv);

      rv = sfparse_parser_item(&sfp, NULL);

      assert_int(SFPARSE_ERR_EOF, ==, rv);
    } else {
      assert_int(SFPARSE_ERR_PARSE, ==, rv);
    }

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_large_generated(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  sfparse_vec unescaped;
  uint8_t buf[16384], sbuf[16];
  uint8_t *p;
  size_t i;
  int len;

  {
    /* large dictionary */
    p = buf;

    for (i = 0; i < 1024; ++i) {
      len =
        snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), "a%d=1, ", (int)i);
      p += len;
    }

    len = (int)(p - buf - 2);

    sfparse_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      assert_size((size_t)len, ==, key.len);
      assert_memory_equal((size_t)len, sbuf, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
    }

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large dictionary key */
    sfparse_parser_bytes_init(
      &sfp,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large list */
    p = buf;

    for (i = 0; i < 1024; ++i) {
      len =
        snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), "a%d, ", (int)i);
      p += len;
    }

    len = (int)(p - buf - 2);

    sfparse_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      assert_int(0, ==, sfparse_parser_list(&sfp, &val));

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_size((size_t)len, ==, val.vec.len);
      assert_memory_equal((size_t)len, sbuf, val.vec.base);
    }

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large parameterised list */
    p = buf;

    for (i = 0; i < 1024; ++i) {
      len = snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), "foo;a%d=1, ",
                     (int)i);
      p += len;
    }

    len = (int)(p - buf - 2);

    sfparse_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      assert_int(0, ==, sfparse_parser_list(&sfp, &val));
      assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
      assert_str_sfparse_vec_eq("foo", &val.vec);

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
      assert_size((size_t)len, ==, key.len);
      assert_memory_equal((size_t)len, sbuf, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
      assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));
    }

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large params */
    p = buf;

    memcpy(buf, "foo", sizeof("foo") - 1);

    p += sizeof("foo") - 1;

    for (i = 0; i < 1024; ++i) {
      len =
        snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), ";a%d=1", (int)i);
      p += len;
    }

    len = (int)(p - buf);

    sfparse_parser_bytes_len_init(&sfp, buf, (size_t)len);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    for (i = 0; i < 1024; ++i) {
      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
      assert_size((size_t)len, ==, key.len);
      assert_memory_equal((size_t)len, sbuf, key.base);
      assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
      assert_int64(1, ==, val.integer);
    }

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large param key */
    sfparse_parser_bytes_init(
      &sfp,
      "foo;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
      "1");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large string */
    sfparse_parser_bytes_init(
      &sfp,
      "\"===================================================================="
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "==============================================\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq(
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "======================================================================"
      "============================================",
      &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large escaped string */
    sfparse_parser_bytes_init(
      &sfp,
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\""
      "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\"
      "\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_true(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);

    unescaped.base = buf;
    sfparse_unescape(&unescaped, &val.vec);

    assert_str_sfparse_vec_eq(
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\""
      "\"\"\"\"\"\"\"\"\"",
      &unescaped);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* large token */
    sfparse_parser_bytes_init(
      &sfp,
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaa");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaa",
      &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }
}

void test_sfparse_parser_examples(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  sfparse_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/examples.json */

  {
    /* Foo-Example */
    sfparse_parser_bytes_init(&sfp, "2; foourl=\"https://foo.example.com/\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foourl", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_false(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);
    assert_str_sfparse_vec_eq("https://foo.example.com/", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-StrListHeader */
    sfparse_parser_bytes_init(
      &sfp, "\"foo\", \"bar\", \"It was the best of times.\"");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_false(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_false(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);
    assert_str_sfparse_vec_eq("bar", &val.vec);

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_false(val.flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING);
    assert_str_sfparse_vec_eq("It was the best of times.", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-StrListListHeader */
    sfparse_parser_bytes_init(
      &sfp, "(\"foo\" \"bar\"), (\"baz\"), (\"bat\" \"one\"), ()");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("bar", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("baz", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("bat", &val.vec);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("one", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-ListListParam */
    sfparse_parser_bytes_init(
      &sfp, "(\"foo\"; a=1;b=2);lvl=5, (\"bar\" \"baz\");lvl=1");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("foo", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("lvl", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("bar", &val.vec);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("baz", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, &val));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("lvl", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-ParamListHeader */
    sfparse_parser_bytes_init(&sfp,
                              "abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w");

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("abc", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("cde_456", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(0, ==, sfparse_parser_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("ghi", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("jk", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(4, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("l", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("q", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("9", &val.vec);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("r", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("w", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_list(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-IntHeader */
    sfparse_parser_bytes_init(&sfp, "1; a; b=?0");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_false(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-DictHeader */
    sfparse_parser_bytes_init(&sfp, "en=\"Applepie\", da=:w4ZibGV0w6ZydGU=:");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("en", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("Applepie", &val.vec);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("da", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("w4ZibGV0w6ZydGU=", &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("\xc3\x86"
                              "blet\xc3\xa6"
                              "rte",
                              &decoded);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-DictHeader (boolean values) */
    sfparse_parser_bytes_init(&sfp, "a=?0, b, c; foo=bar");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_false(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foo", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("bar", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-DictListHeader */
    sfparse_parser_bytes_init(&sfp, "rating=1.5, feelings=(joy sadness)");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("rating", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(15, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("feelings", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("joy", &val.vec);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("sadness", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-MixDict */
    sfparse_parser_bytes_init(&sfp, "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("a", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("b", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(3, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("c", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(4, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("aa", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("bb", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("d", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INNER_LIST, ==, val.type);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);

    assert_int(0, ==, sfparse_parser_inner_list(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(6, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_inner_list(&sfp, NULL));

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("valid", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-Hdr (dictionary on one line) */
    sfparse_parser_bytes_init(&sfp, "foo=1, bar=2");

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foo", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(1, ==, val.integer);

    assert_int(0, ==, sfparse_parser_dict(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("bar", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(2, ==, val.integer);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_dict(&sfp, NULL, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-IntItemHeader */
    sfparse_parser_bytes_init(&sfp, "5");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-IntItemHeader (params) */
    sfparse_parser_bytes_init(&sfp, "5; foo=bar");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(5, ==, val.integer);

    assert_int(0, ==, sfparse_parser_param(&sfp, &key, &val));
    assert_str_sfparse_vec_eq("foo", &key);
    assert_enum(sfparse_type, SFPARSE_TYPE_TOKEN, ==, val.type);
    assert_str_sfparse_vec_eq("bar", &val.vec);

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_param(&sfp, NULL, NULL));

    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-IntegerHeader */
    sfparse_parser_bytes_init(&sfp, "42");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_INTEGER, ==, val.type);
    assert_int64(42, ==, val.integer);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-FloatHeader */
    sfparse_parser_bytes_init(&sfp, "4.5");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_DECIMAL, ==, val.type);
    assert_int64(45, ==, val.decimal.numer);
    assert_int64(10, ==, val.decimal.denom);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-StringHeader */
    sfparse_parser_bytes_init(&sfp, "\"hello world\"");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_STRING, ==, val.type);
    assert_str_sfparse_vec_eq("hello world", &val.vec);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-BinaryHdr */
    sfparse_parser_bytes_init(&sfp,
                              ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BYTESEQ, ==, val.type);
    assert_str_sfparse_vec_eq("cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==",
                              &val.vec);

    decoded.base = buf;
    sfparse_base64decode(&decoded, &val.vec);

    assert_str_sfparse_vec_eq("pretend this is binary content.", &decoded);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }

  {
    /* Example-BoolHdr */
    sfparse_parser_bytes_init(&sfp, "?1");

    assert_int(0, ==, sfparse_parser_item(&sfp, &val));
    assert_enum(sfparse_type, SFPARSE_TYPE_BOOLEAN, ==, val.type);
    assert_true(val.boolean);
    assert_int(SFPARSE_ERR_EOF, ==, sfparse_parser_item(&sfp, NULL));

    sfparse_parser_bytes_free();
  }
}
