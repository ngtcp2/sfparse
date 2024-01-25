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

#include <CUnit/CUnit.h>

#include "sfparse.h"

#define sf_parser_bytes_init(SFP, S)                                           \
  {                                                                            \
    uint8_t *input_buffer = malloc(sizeof(S) - 1);                             \
    memcpy(input_buffer, (S), sizeof(S) - 1);                                  \
    sf_parser_init((SFP), input_buffer, sizeof(S) - 1);

#define sf_parser_bytes_len_init(SFP, DATA, DATALEN)                           \
  {                                                                            \
    uint8_t *input_buffer = malloc((DATALEN));                                 \
    memcpy(input_buffer, (DATA), (DATALEN));                                   \
    sf_parser_init((SFP), input_buffer, (DATALEN));

#define sf_parser_bytes_free()                                                 \
  free(input_buffer);                                                          \
  }

static int str_sf_vec_eq(const char *s, const sf_vec *v) {
  return strlen(s) == v->len &&
         (v->len == 0 || 0 == memcmp(s, v->base, v->len));
}

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

void test_sf_parser_item_skip(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  {
    /* skip empty parameter */
    sf_parser_bytes_init(&sfp, "a");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sf_parser_bytes_init(&sfp, "a;f=1000000009;g=1000000007");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip boolean parameter */
    sf_parser_bytes_init(&sfp, "a;f");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with empty parameter */
    sf_parser_bytes_init(&sfp, "(a)");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with non-empty parameter */
    sf_parser_bytes_init(&sfp, "(a);f=1000000009;g=1000000007");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sf_parser_bytes_init(&sfp, "(a);f");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sf_parser_bytes_init(&sfp, "(a);f");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("f", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sf_parser_bytes_init(&sfp, "(1;foo=100 2;bar)");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));
    sf_parser_bytes_free();
  }
}

void test_sf_parser_dict_skip(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  {
    /* skip empty parameter */
    sf_parser_bytes_init(&sfp, "a=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sf_parser_bytes_init(&sfp, "a=3;f=999;g=1.23");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip boolean parameter */
    sf_parser_bytes_init(&sfp, "a=3;f");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list */
    sf_parser_bytes_init(&sfp, "a=(1 2 3) , b=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with parameter */
    sf_parser_bytes_init(&sfp, "a=(1 2 3);f=a;g=b , b=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sf_parser_bytes_init(&sfp, "a=(1 2 3);f;g , b=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sf_parser_bytes_init(&sfp, "a=(1 2 3);f;g , b=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("f", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("g", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sf_parser_bytes_init(&sfp, "a=(1;foo=100 2;bar)");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_list_skip(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  {
    /* skip empty parameter */
    sf_parser_bytes_init(&sfp, "a");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip non-empty parameter */
    sf_parser_bytes_init(&sfp, "a;fff=1;ggg=9");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list */
    sf_parser_bytes_init(&sfp, "(1 2 3) , 333");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(333 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with parameter */
    sf_parser_bytes_init(&sfp, "(1 2 3);f=a;g=b , 333");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(333 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list with boolean parameter */
    sf_parser_bytes_init(&sfp, "(1 2 3);f;g , 333");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(333 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list but read parameter */
    sf_parser_bytes_init(&sfp, "(1 2 3);f;g , 333");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("f", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("g", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(333 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* skip inner list item parameter */
    sf_parser_bytes_init(&sfp, "(1;foo=100 2;bar)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_byteseq(void) {
  sf_parser sfp;
  sf_value val;
  sf_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/binary.json */

  {
    /* basic binary */
    sf_parser_bytes_init(&sfp, ":aGVsbG8=:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("aGVsbG8=", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("hello", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* empty binary */
    sf_parser_bytes_init(&sfp, "::");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* bad paddding */
    sf_parser_bytes_init(&sfp, ":aGVsbG8:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("aGVsbG8", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("hello", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* bad end delimiter */
    sf_parser_bytes_init(&sfp, ":aGVsbG8=");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace */
    sf_parser_bytes_init(&sfp, ":aGVsb G8=:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra chars */
    sf_parser_bytes_init(&sfp, ":aGVsbG!8=:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* suffix chars */
    sf_parser_bytes_init(&sfp, ":aGVsbG8=!:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* non-zero pad bits */
    sf_parser_bytes_init(&sfp, ":iZ==:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("iZ==", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\x89", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* non-ASCII binary */
    sf_parser_bytes_init(&sfp, ":/+Ah:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("/+Ah", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\xff\xe0!", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* base64url binary */
    sf_parser_bytes_init(&sfp, ":_-Ah:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* missing closing DQUOTE */
    sf_parser_bytes_init(&sfp, "z,:1jk=");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("z", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Just ':' */
    sf_parser_bytes_init(&sfp, ":");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Just single '=' */
    sf_parser_bytes_init(&sfp, ":=:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Two '=' */
    sf_parser_bytes_init(&sfp, ":==:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Three '=' */
    sf_parser_bytes_init(&sfp, ":===:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Four '=' */
    sf_parser_bytes_init(&sfp, ":====:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Single letter never be a base64 encoded string */
    sf_parser_bytes_init(&sfp, ":K:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Omitting all padding and non-zero pad bits */
    sf_parser_bytes_init(&sfp, ":K7:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("K7", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\x2b", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Omitting a single padding and non-zero pad bits */
    sf_parser_bytes_init(&sfp, ":K7=:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("K7=", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\x2b", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Omitting a padding and non-zero pad bits */
    sf_parser_bytes_init(&sfp, ":K73:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("K73", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\x2b\xbd", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Not omitting a padding but non-zero pad bits */
    sf_parser_bytes_init(&sfp, ":K73=:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("K73=", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\x2b\xbd", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Padding in the middle of encoded string */
    sf_parser_bytes_init(&sfp, ":ab=a:");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_boolean(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/boolean.json */

  {
    /* basic true boolean */
    sf_parser_bytes_init(&sfp, "?1");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* basic false boolean */
    sf_parser_bytes_init(&sfp, "?0");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(0 == val.boolean);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* unknown boolean */
    sf_parser_bytes_init(&sfp, "?Q");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace boolean */
    sf_parser_bytes_init(&sfp, "? 1");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* negative zero boolean */
    sf_parser_bytes_init(&sfp, "?-0");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* T boolean */
    sf_parser_bytes_init(&sfp, "?T");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* F boolean */
    sf_parser_bytes_init(&sfp, "?F");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* t boolean */
    sf_parser_bytes_init(&sfp, "?t");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* f boolean */
    sf_parser_bytes_init(&sfp, "?f");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* spelled-out True boolean */
    sf_parser_bytes_init(&sfp, "?True");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* spelled-out False boolean */
    sf_parser_bytes_init(&sfp, "?False");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '?' */
    sf_parser_bytes_init(&sfp, "?");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_number(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/number.json */

  {
    /* basic integer */
    sf_parser_bytes_init(&sfp, "42");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* zero integer */
    sf_parser_bytes_init(&sfp, "0");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(0 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* negative zero */
    sf_parser_bytes_init(&sfp, "-0");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(0 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* double negative zero */
    sf_parser_bytes_init(&sfp, "--0");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* negative integer */
    sf_parser_bytes_init(&sfp, "-42");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(-42 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* leading 0 integer" */
    sf_parser_bytes_init(&sfp, "042");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* leading 0 negative integer */
    sf_parser_bytes_init(&sfp, "-042");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(-42 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* leading 0 zero */
    sf_parser_bytes_init(&sfp, "00");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(0 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* comma */
    sf_parser_bytes_init(&sfp, "2,3");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);
    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* negative non-DIGIT first character */
    sf_parser_bytes_init(&sfp, "-a23");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* sign out of place */
    sf_parser_bytes_init(&sfp, "4-2");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(4 == val.integer);
    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after sign */
    sf_parser_bytes_init(&sfp, "- 42");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* long integer */
    sf_parser_bytes_init(&sfp, "123456789012345");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(123456789012345 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* long negative integer */
    sf_parser_bytes_init(&sfp, "-123456789012345");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(-123456789012345 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* too long integer */
    sf_parser_bytes_init(&sfp, "1234567890123456");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* negative too long integer */
    sf_parser_bytes_init(&sfp, "-1234567890123456");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* simple decimal */
    sf_parser_bytes_init(&sfp, "1.23");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(123 == val.decimal.numer);
    CU_ASSERT(100 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* negative decimal */
    sf_parser_bytes_init(&sfp, "-1.23");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(-123 == val.decimal.numer);
    CU_ASSERT(100 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* decimal, whitespace after decimal */
    sf_parser_bytes_init(&sfp, "1. 23");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* decimal, whitespace before decimal" */
    sf_parser_bytes_init(&sfp, "1 .23");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);
    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* negative decimal, whitespace after sign */
    sf_parser_bytes_init(&sfp, "- 1.23");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* tricky precision decimal */
    sf_parser_bytes_init(&sfp, "123456789012.1");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(1234567890121 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* double decimal decimal */
    sf_parser_bytes_init(&sfp, "1.5.4");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(15 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);
    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* adjacent double decimal decimal */
    sf_parser_bytes_init(&sfp, "1..4");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* decimal with three fractional digits */
    sf_parser_bytes_init(&sfp, "1.123");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(1123 == val.decimal.numer);
    CU_ASSERT(1000 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* negative decimal with three fractional digits */
    sf_parser_bytes_init(&sfp, "-1.123");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(-1123 == val.decimal.numer);
    CU_ASSERT(1000 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* decimal with four fractional digits */
    sf_parser_bytes_init(&sfp, "1.1234");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* negative decimal with four fractional digits */
    sf_parser_bytes_init(&sfp, "-1.1234");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* decimal with thirteen integer digits */
    sf_parser_bytes_init(&sfp, "1234567890123.0");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* negative decimal with thirteen integer digits */
    sf_parser_bytes_init(&sfp, "-1234567890123.0");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* No digits */
    sf_parser_bytes_init(&sfp, "-a");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* No digits before '.' */
    sf_parser_bytes_init(&sfp, "-.1");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_date(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/date.json */

  {
    /* date - 1970-01-01 00:00:00 */
    sf_parser_bytes_init(&sfp, "@0");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DATE == val.type);
    CU_ASSERT(0 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* date - 2022-08-04 01:57:13 */
    sf_parser_bytes_init(&sfp, "@1659578233");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DATE == val.type);
    CU_ASSERT(1659578233 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* date - 1917-05-30 22:02:47 */
    sf_parser_bytes_init(&sfp, "@-1659578233");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DATE == val.type);
    CU_ASSERT(-1659578233 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* date - 2^31 */
    sf_parser_bytes_init(&sfp, "@2147483648");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DATE == val.type);
    CU_ASSERT(2147483648 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* date - 2^32 */
    sf_parser_bytes_init(&sfp, "@4294967296");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DATE == val.type);
    CU_ASSERT(4294967296 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* date - decimal */
    sf_parser_bytes_init(&sfp, "@1659578233.12");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '@' */
    sf_parser_bytes_init(&sfp, "@");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_string(void) {
  sf_parser sfp;
  sf_value val;
  sf_vec unescaped;
  uint8_t buf[256];

  /* https://github.com/httpwg/structured-field-tests/blob/main/string.json */

  {
    /* basic string */
    sf_parser_bytes_init(&sfp, "\"foo bar\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo bar", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* empty string */
    sf_parser_bytes_init(&sfp, "\"\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* long string */
    sf_parser_bytes_init(
        &sfp,
        "\"foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo \"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq(
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo foo "
        "foo foo foo foo foo foo foo foo foo foo foo foo foo foo ",
        &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* whitespace string */
    sf_parser_bytes_init(&sfp, "\"   \"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("   ", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* non-ascii string */
    sf_parser_bytes_init(&sfp, "\"füü\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* tab in string" */
    sf_parser_bytes_init(&sfp, "\"\\t\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* newline in string */
    sf_parser_bytes_init(&sfp, "\" \\n \"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* single quoted string */
    sf_parser_bytes_init(&sfp, "'foo'");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* unbalanced string */
    sf_parser_bytes_init(&sfp, "\"foo");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* string quoting */
    sf_parser_bytes_init(&sfp, "\"foo \\\"bar\\\" \\\\ baz\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo \\\"bar\\\" \\\\ baz", &val.vec));
    CU_ASSERT(val.flags & SF_VALUE_FLAG_ESCAPED_STRING);

    unescaped.base = buf;
    sf_unescape(&unescaped, &val.vec);

    CU_ASSERT(str_sf_vec_eq("foo \"bar\" \\ baz", &unescaped));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* bad string quoting */
    sf_parser_bytes_init(&sfp, "\"foo \\,\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* ending string quote */
    sf_parser_bytes_init(&sfp, "\"foo \\\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* abruptly ending string quote */
    sf_parser_bytes_init(&sfp, "\"foo \\");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just '"' */
    sf_parser_bytes_init(&sfp, "\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_token(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/token.json */

  {
    /* basic token - item */
    sf_parser_bytes_init(&sfp, "a_b-c.d3:f%00/*");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a_b-c.d3:f%00/*", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* token with capitals - item */
    sf_parser_bytes_init(&sfp, "fooBar");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("fooBar", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* token starting with capitals - item */
    sf_parser_bytes_init(&sfp, "FooBar");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("FooBar", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* basic token - list */
    sf_parser_bytes_init(&sfp, "a_b-c3/*");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a_b-c3/*", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* token with capitals - list */
    sf_parser_bytes_init(&sfp, "fooBar");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("fooBar", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* token starting with capitals - list */
    sf_parser_bytes_init(&sfp, "FooBar");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("FooBar", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_dispstring(void) {
  sf_parser sfp;
  sf_value val;
  sf_vec decoded;
  uint8_t buf[128];

  /* https://github.com/httpwg/structured-field-tests/blob/main/display-string.json
   */

  {
    /* basic display string (ascii content) */
    sf_parser_bytes_init(&sfp, "%\"foo bar\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo bar", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("foo bar", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* all printable ascii */
    sf_parser_bytes_init(&sfp, "%\" "
                               "!%22#$%25&'()*+,-./"
                               "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
                               "^_`abcdefghijklmnopqrstuvwxyz{|}~\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq(" !%22#$%25&'()*+,-./"
                            "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]"
                            "^_`abcdefghijklmnopqrstuvwxyz{|}~",
                            &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq(" !\"#$%&'()*+,-./"
                            "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                            "abcdefghijklmnopqrstuvwxyz{|}~",
                            &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* non-ascii display string (uppercase escaping) */
    sf_parser_bytes_init(&sfp, "%\"f%C3%BC%C3%BC\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* non-ascii display string (lowercase escaping) */
    sf_parser_bytes_init(&sfp, "%\"f%c3%bc%c3%bc\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("f%c3%bc%c3%bc", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("füü", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* tab in display string */
    sf_parser_bytes_init(&sfp, "%\"\t\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* newline in display string */
    sf_parser_bytes_init(&sfp, "%\"\n\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* single quoted display string */
    sf_parser_bytes_init(&sfp, "%'foo'");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* unquoted display string */
    sf_parser_bytes_init(&sfp, "%foo");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* display string missing initial quote */
    sf_parser_bytes_init(&sfp, "%foo\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* unbalanced display string */
    sf_parser_bytes_init(&sfp, "%\"foo");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* display string quoting */
    sf_parser_bytes_init(&sfp, "%\"foo %22bar%22 \\ baz\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo %22bar%22 \\ baz", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("foo \"bar\" \\ baz", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* bad display string escaping */
    sf_parser_bytes_init(&sfp, "%\"foo %a");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 2-byte seq) */
    sf_parser_bytes_init(&sfp, "%\"%c3%28\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid sequence id) */
    sf_parser_bytes_init(&sfp, "%\"%a0%a1\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 3-byte seq) */
    sf_parser_bytes_init(&sfp, "%\"%e2%28%a1\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad display string utf-8 (invalid 4-byte seq) */
    sf_parser_bytes_init(&sfp, "%\"%f0%28%8c%28\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* BOM in display string */
    sf_parser_bytes_init(&sfp, "%\"BOM: %ef%bb%bf\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("BOM: %ef%bb%bf", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("BOM: \xef\xbb\xbf", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* base UTF-8 string */
    sf_parser_bytes_init(
        &sfp,
        "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq(
        "%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c",
        &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\xe3\x81\x93\xe3\x82\x93\xe3\x81\xab\xe3\x81\xa1"
                            "\xe3\x81\xaf\xe4\xb8\x96\xe7\x95\x8c",
                            &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* truncated UTF-8 string */
    sf_parser_bytes_init(&sfp, "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81"
                               "%a1%e3%81%af%e4%b8%96%e7%95\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Just '%' */
    sf_parser_bytes_init(&sfp, "%");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* just '%"' */
    sf_parser_bytes_init(&sfp, "%\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty dispstring */
    sf_parser_bytes_init(&sfp, "%\"\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* base UTF-8 string without closing DQUOTE */
    sf_parser_bytes_init(
        &sfp,
        "%\"%e3%81%93%e3%82%93%e3%81%ab%e3%81%a1%e3%81%af%e4%b8%96%e7%95%8c");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* illegal character */
    sf_parser_bytes_init(&sfp, "%\""
                               "\x00"
                               "\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad percent encoding (first half) */
    sf_parser_bytes_init(&sfp, "%\"%qa\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad percent encoding (second half) */
    sf_parser_bytes_init(&sfp, "%\"%aq\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad percent encoding (missing 2 bytes) */
    sf_parser_bytes_init(&sfp, "%\"%\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad percent encoding (missing 2nd byte) */
    sf_parser_bytes_init(&sfp, "%\"%a\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* ASCII string */
    sf_parser_bytes_init(&sfp, "%\"hello world\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(str_sf_vec_eq("hello world", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("hello world", &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* ASCII + percent-encoded UTF-8 byte sequence */
    sf_parser_bytes_init(&sfp,
                         "%\"This is intended for display to %c3%bcsers.\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DISPSTRING == val.type);
    CU_ASSERT(
        str_sf_vec_eq("This is intended for display to %c3%bcsers.", &val.vec));

    decoded.base = buf;
    sf_pctdecode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("This is intended for display to "
                            "\xc3\xbc"
                            "sers.",
                            &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* overlong 2 byte sequence */
    sf_parser_bytes_init(&sfp, "%\"%c0%af\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* Uppercase percent-encoded string is invalid */
    sf_parser_bytes_init(&sfp,
                         "%\"This is intended for display to %C3%BCsers.\"");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_dictionary(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  sf_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/dictionary.json
   */

  {
    /* basic dictionary */
    sf_parser_bytes_init(&sfp, "en=\"Applepie\", da=:w4ZibGV0w6ZydGUK:");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("en", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("Applepie", &val.vec));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("da", &key));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("w4ZibGV0w6ZydGUK", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\xc3\x86"
                            "blet\xc3\xa6"
                            "rte\n",
                            &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, NULL));

    sf_parser_bytes_free();
  }

  {
    /* empty dictionary */
    sf_parser_bytes_init(&sfp, "");

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* single item dictionary */
    sf_parser_bytes_init(&sfp, "a=1");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, NULL));

    sf_parser_bytes_free();
  }

  {
    /* list item dictionary */
    sf_parser_bytes_init(&sfp, "a=(1 2)");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* single list item dictionary */
    sf_parser_bytes_init(&sfp, "a=(1)");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty list item dictionary */
    sf_parser_bytes_init(&sfp, "a=()");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* no whitespace dictionary */
    sf_parser_bytes_init(&sfp, "a=1,b=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace dictionary */
    sf_parser_bytes_init(&sfp, "a=1 ,  b=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* tab separated dictionary */
    sf_parser_bytes_init(&sfp, "a=1\t,\tb=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* leading whitespace dictionary */
    sf_parser_bytes_init(&sfp, "     a=1 ,  b=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace before = dictionary */
    sf_parser_bytes_init(&sfp, "a =1, b=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after = dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b= 2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  /* two lines dictionary */
  /* sf_parser does not support merging 2 lines */

  {
    /* missing value dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b, c=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* all missing value dictionary */
    sf_parser_bytes_init(&sfp, "a, b, c");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* start missing value dictionary */
    sf_parser_bytes_init(&sfp, "a, b=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* end missing value dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* missing value with params dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b;foo=9, c=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foo", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(9 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* explicit true value with params dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b=?1;foo=9, c=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foo", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(9 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* trailing comma dictionary */
    sf_parser_bytes_init(&sfp, "a=1, b=2,");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty item dictionary */
    sf_parser_bytes_init(&sfp, "a=1,,b=2,");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* duplicate key dictionary */
    /* sf_parser does no effort to find duplicates. */
    sf_parser_bytes_init(&sfp, "a=1,b=2,a=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* numeric key dictionary */
    sf_parser_bytes_init(&sfp, "a=1,1b=2,a=1");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* uppercase key dictionary */
    sf_parser_bytes_init(&sfp, "a=1,B=2,a=1");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* bad key dictionary */
    sf_parser_bytes_init(&sfp, "a=1,b!=2,a=1");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Empty value */
    sf_parser_bytes_init(&sfp, "a=");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_list(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/list.json */

  {
    /* basic list */
    sf_parser_bytes_init(&sfp, "1, 42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty list" */
    sf_parser_bytes_init(&sfp, "");

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* leading SP list */
    sf_parser_bytes_init(&sfp, "  42, 43");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(43 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* single item list */
    sf_parser_bytes_init(&sfp, "42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no whitespace list */
    sf_parser_bytes_init(&sfp, "1,42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace list */
    sf_parser_bytes_init(&sfp, "1 , 42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* tab separated list */
    sf_parser_bytes_init(&sfp, "1\t,\t42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* two line list */
  /* sf_parser does not support merging 2 lines */

  {
    /* trailing comma list */
    sf_parser_bytes_init(&sfp, "1, 42,");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty item list */
    sf_parser_bytes_init(&sfp, "1,,42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* empty item list (multiple field lines) */
  /* sf_parser does not support merging 2 lines */
}

void test_sf_parser_list_list(void) {
  sf_parser sfp;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/listlist.json */

  {
    /* basic list of lists */
    sf_parser_bytes_init(&sfp, "(1 2), (42 43)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(43 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* single item list of lists */
    sf_parser_bytes_init(&sfp, "(42)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty item list of lists" */
    sf_parser_bytes_init(&sfp, "()");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty middle item list of lists */
    sf_parser_bytes_init(&sfp, "(1),(),(42)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace list of lists */
    sf_parser_bytes_init(&sfp, "(  1  42  )");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* wrong whitespace list of lists */
    sf_parser_bytes_init(&sfp, "(1\t 42)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no trailing parenthesis list of lists */
    sf_parser_bytes_init(&sfp, "(1 42");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no trailing parenthesis middle list of lists */
    sf_parser_bytes_init(&sfp, "(1 2, (42 43)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no spaces in inner-list */
    sf_parser_bytes_init(&sfp, "(abc\"def\"?0123*dXZ3*xyz)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no closing parenthesis */
    sf_parser_bytes_init(&sfp, "(");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* Just ')' */
    sf_parser_bytes_init(&sfp, ")");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_param_dict(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-dict.json
   */

  {
    /* basic parameterised dict */
    sf_parser_bytes_init(&sfp,
                         "abc=123;a=1;b=2, def=456, ghi=789;q=9;r=\"+w\"");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("abc", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(123 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("def", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(456 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("ghi", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(789 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(9 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("r", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("+w", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* single item parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b; q=1.0");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* list item parameterised dictionary */
    sf_parser_bytes_init(&sfp, "a=(1 2); q=1.0");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* missing parameter value parameterised dict */
    sf_parser_bytes_init(&sfp, "a=3;c;d=5");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("d", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* terminal missing parameter value parameterised dict */
    sf_parser_bytes_init(&sfp, "a=3;c=5;d");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("d", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* no whitespace parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b;c=1,d=e;f=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("d", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("e", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("f", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace before = parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b;q =0.5");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after = parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b;q= 0.5");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_param(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace before ; parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b ;q=0.5");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after ; parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b; q=0.5");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(5 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace parameterised dict */
    sf_parser_bytes_init(&sfp, "a=b;  c=1  ,  d=e; f=2; g=3");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("d", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("e", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("f", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("g", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  /* two lines parameterised list */
  /* sf_parser does not support merging 2 lines */

  {
    /* trailing comma parameterised list */
    sf_parser_bytes_init(&sfp, "a=b; q=1.0,");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty item parameterised list */
    sf_parser_bytes_init(&sfp, "a=b; q=1.0,,c=d");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sf_parser_bytes_init(&sfp, "a=b;c=");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("b", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_param(&sfp, &key, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_param_list(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-list.json
   */

  {
    /* basic parameterised list */
    sf_parser_bytes_init(&sfp, "abc_123;a=1;b=2; cdef_456, ghi;q=9;r=\"+w\"");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc_123", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("cdef_456", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("ghi", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(9 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("r", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("+w", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* single item parameterised list */
    sf_parser_bytes_init(&sfp, "text/html;q=1.0");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* missing parameter value parameterised list */
    sf_parser_bytes_init(&sfp, "text/html;a;q=1.0");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* missing terminal parameter value parameterised list */
    sf_parser_bytes_init(&sfp, "text/html;q=1.0;a");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(10 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* no whitespace parameterised list */
    sf_parser_bytes_init(&sfp, "text/html,text/plain;q=0.5");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(5 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace before = parameterised list */
    sf_parser_bytes_init(&sfp, "text/html, text/plain;q =0.5");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after = parameterised list */
    sf_parser_bytes_init(&sfp, "text/html, text/plain;q= 0.5");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_param(&sfp, &key, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace before ; parameterised list */
    sf_parser_bytes_init(&sfp, "text/html, text/plain ;q=0.5");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* whitespace after ; parameterised list */
    sf_parser_bytes_init(&sfp, "text/html, text/plain; q=0.5");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(5 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* extra whitespace parameterised list */
    sf_parser_bytes_init(&sfp,
                         "text/html  ,  text/plain;  q=0.5;  charset=utf-8");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(5 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("charset", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("utf-8", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* two lines parameterised list */
  /* sf_parser does not support merging 2 lines */

  {
    /* trailing comma parameterised list */
    sf_parser_bytes_init(&sfp, "text/html,text/plain;q=0.5,");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/plain", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(5 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* empty item parameterised list */
    sf_parser_bytes_init(&sfp, "text/html,,text/plain;q=0.5,");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("text/html", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sf_parser_bytes_init(&sfp, "a;b=");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_param(&sfp, &key, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_param_list_list(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  /* https://github.com/httpwg/structured-field-tests/blob/main/param-listlist.json
   */

  {
    /* parameterised inner list */
    sf_parser_bytes_init(&sfp, "(abc_123);a=1;b=2, cdef_456");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc_123", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("cdef_456", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* parameterised inner list item */
    sf_parser_bytes_init(&sfp, "(abc_123;a=1;b=2;cdef_456)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc_123", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("cdef_456", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* parameterised inner list with parameterised item */
    sf_parser_bytes_init(&sfp, "(abc_123;a=1;b=2);cdef_456");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc_123", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("cdef_456", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, &val));

    sf_parser_bytes_free();
  }

  /* Additional tests */

  {
    /* empty parameter value */
    sf_parser_bytes_init(&sfp, "(a;b= 1)");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("a", &val.vec));

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_param(&sfp, &key, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_number_generated(void) {
  sf_parser sfp;
  sf_value val;
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

      sf_parser_bytes_len_init(&sfp, buf, len);

      CU_ASSERT(0 == sf_parser_item(&sfp, &val));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(integer == val.integer);

      sf_parser_bytes_free();
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

        sf_parser_bytes_len_init(&sfp, buf, len + 1 + flen);

        CU_ASSERT(0 == sf_parser_item(&sfp, &val));
        CU_ASSERT(SF_TYPE_DECIMAL == val.type);
        CU_ASSERT(integer == val.decimal.numer);
        CU_ASSERT(denom == val.decimal.denom);
        CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

        sf_parser_bytes_free();
      }
    }
  }

  {
    /* too many digit 0 decimal */
    sf_parser_bytes_init(&sfp, "000000000000000.0");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* too many fractional digits 0 decimal */
    sf_parser_bytes_init(&sfp, "000000000000.0000");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* too many digit 9 decimal */
    sf_parser_bytes_init(&sfp, "999999999999999.9");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }

  {
    /* too many fractional digits 9 decimal */
    sf_parser_bytes_init(&sfp, "999999999999.9999");

    CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, &val));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_string_generated(void) {
  sf_parser sfp;
  sf_value val;
  size_t i;
  uint8_t buf[16];
  int rv;

  /* 0x?? in string */
  for (i = 0; i < 256; ++i) {
    buf[0] = '"';
    buf[1] = ' ';
    buf[2] = (uint8_t)i;
    buf[3] = ' ';
    buf[4] = '"';

    sf_parser_bytes_len_init(&sfp, buf, 5);

    rv = sf_parser_item(&sfp, &val);

    if (i == 0x20 || i == 0x21 || (0x23 <= i && i <= 0x5b) ||
        (0x5d <= i && i <= 0x7e) || i == 0x22) {
      CU_ASSERT(0 == rv);

      rv = sf_parser_item(&sfp, NULL);

      if (i == 0x22) {
        CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
      } else {
        CU_ASSERT(SF_ERR_EOF == rv);
      }
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }

  /* Escaped 0x?? in string */
  for (i = 0; i < 256; ++i) {
    buf[0] = '"';
    buf[1] = '\\';
    buf[2] = (uint8_t)i;
    buf[3] = '"';

    sf_parser_bytes_len_init(&sfp, buf, 4);

    rv = sf_parser_item(&sfp, &val);

    if (i == '\\' || i == '"') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }
}

void test_sf_parser_token_generated(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  size_t i;
  uint8_t buf[16];
  int rv;

  /* 0x?? in token */
  for (i = 0; i < 256; ++i) {
    buf[0] = 'a';
    buf[1] = (uint8_t)i;
    buf[2] = 'a';

    sf_parser_bytes_len_init(&sfp, buf, 3);

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));

    if (is_token_char((uint8_t)i)) {
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(3 == val.vec.len);
      CU_ASSERT(0 == memcmp(buf, val.vec.base, 3));
      CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));
    } else {
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("a", &val.vec));

      if (i == ';') {
        CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
        CU_ASSERT(str_sf_vec_eq("a", &key));
        CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
        CU_ASSERT(1 == val.boolean);
        CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, &key, &val));
        CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, &val));
      } else {
        CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));
      }
    }

    sf_parser_bytes_free();
  }

  /* 0x?? starting a token */
  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = 'a';

    sf_parser_bytes_len_init(&sfp, buf, 2);

    rv = sf_parser_item(&sfp, &val);

    if (is_first_token_char((uint8_t)i)) {
      CU_ASSERT(0 == rv);
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(2 == val.vec.len);
      CU_ASSERT(0 == memcmp(buf, val.vec.base, 2));
      CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));
    } else if (i == ' ') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("a", &val.vec));
      CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));
    } else if ('0' <= i && i <= '9') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT((int64_t)(i - '0') == val.integer);
      CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_item(&sfp, NULL));
    } else if (i == '(') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(SF_TYPE_INNER_LIST == val.type);
      CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("a", &val.vec));
      CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_inner_list(&sfp, NULL));
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }
}

void test_sf_parser_key_generated(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  size_t i;
  uint8_t buf[16];
  int rv;
  int len;

  /* 0x?? as a single-character dictionary key */
  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = '=';
    buf[2] = '1';

    sf_parser_bytes_len_init(&sfp, buf, 3);

    rv = sf_parser_dict(&sfp, &key, &val);

    if (('a' <= i && i <= 'z') || i == '*') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(1 == key.len);
      CU_ASSERT((uint8_t)i == key.base[0]);
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }

  /* 0x?? in dictionary key */
  for (i = 0; i < 256; ++i) {
    buf[0] = 'a';
    buf[1] = (uint8_t)i;
    buf[2] = 'a';
    buf[3] = '=';
    buf[4] = '1';

    sf_parser_bytes_len_init(&sfp, buf, 5);

    rv = sf_parser_dict(&sfp, &key, &val);

    if (is_key_char((uint8_t)i)) {
      CU_ASSERT(0 == rv);
      CU_ASSERT(3 == key.len);
      CU_ASSERT(0 == memcmp(buf, key.base, 3));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
    } else if (i == '=') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("a", &val.vec));
      CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, NULL, NULL));
    } else {
      CU_ASSERT(0 == rv);
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
      CU_ASSERT(1 == val.boolean);

      if (i == ',') {
        CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
        CU_ASSERT(str_sf_vec_eq("a", &key));
        CU_ASSERT(SF_TYPE_INTEGER == val.type);
        CU_ASSERT(1 == val.integer);
        CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
      } else if (i == ';') {
        CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
        CU_ASSERT(str_sf_vec_eq("a", &key));
        CU_ASSERT(SF_TYPE_INTEGER == val.type);
        CU_ASSERT(1 == val.integer);
        CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
        CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
      } else {
        CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_dict(&sfp, NULL, NULL));
      }
    }

    sf_parser_bytes_free();
  }

  /* 0x?? starting a dictionary key */
  for (i = 0; i < 256; ++i) {
    buf[0] = (uint8_t)i;
    buf[1] = 'a';
    buf[2] = '=';
    buf[3] = '1';

    sf_parser_bytes_len_init(&sfp, buf, 4);

    rv = sf_parser_dict(&sfp, &key, &val);

    if (is_first_key_char((uint8_t)i)) {
      CU_ASSERT(0 == rv);
      CU_ASSERT(2 == key.len);
      CU_ASSERT(0 == memcmp(buf, key.base, 2));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
    } else if (i == ' ') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }

  /* 0x?? in parameterised list key */
  for (i = 0; i < 256; ++i) {
    len = snprintf((char *)buf, sizeof(buf), "foo; a%ca=1", (char)i);

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));

    if (is_key_char((uint8_t)i)) {
      CU_ASSERT(3 == key.len);
      CU_ASSERT(0 == memcmp(buf + 5, key.base, 3));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
      CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));
    } else if (i == '=') {
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("a", &val.vec));
      CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
      CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, NULL));
    } else {
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
      CU_ASSERT(1 == val.boolean);

      if (i == ';') {
        CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
        CU_ASSERT(str_sf_vec_eq("a", &key));
        CU_ASSERT(SF_TYPE_INTEGER == val.type);
        CU_ASSERT(1 == val.integer);
        CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
        CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));
      } else {
        CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

        rv = sf_parser_list(&sfp, &val);

        if (i == ',') {
          CU_ASSERT(0 == rv);
          CU_ASSERT(SF_TYPE_TOKEN == val.type);
          CU_ASSERT(str_sf_vec_eq("a", &val.vec));
          CU_ASSERT(SF_ERR_PARSE_ERROR == sf_parser_list(&sfp, NULL));
        } else {
          CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
        }
      }
    }

    sf_parser_bytes_free();
  }

  /* 0x?? starting a parameterised list key */
  for (i = 0; i < 256; ++i) {
    len = snprintf((char *)buf, sizeof(buf), "foo; %ca=1", (char)i);

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    rv = sf_parser_param(&sfp, &key, &val);

    if (is_first_key_char((uint8_t)i)) {
      CU_ASSERT(0 == rv);
      CU_ASSERT(2 == key.len);
      CU_ASSERT(0 == memcmp(buf + 5, key.base, 2));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
      CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));
    } else if (i == ' ') {
      CU_ASSERT(0 == rv);
      CU_ASSERT(str_sf_vec_eq("a", &key));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
      CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));
    } else {
      CU_ASSERT(SF_ERR_PARSE_ERROR == rv);
    }

    sf_parser_bytes_free();
  }
}

void test_sf_parser_large_generated(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  sf_vec unescaped;
  uint8_t buf[16384], sbuf[16];
  uint8_t *p;
  size_t i;
  int len;

  {
    /* large dictionary */
    p = buf;

    for (i = 0; i < 1024; ++i) {
      len = snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), "a%d=1, ",
                     (int)i);
      p += len;
    }

    len = (int)(p - buf - 2);

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      CU_ASSERT((size_t)len == key.len);
      CU_ASSERT(0 == memcmp(sbuf, key.base, (size_t)len));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
    }

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large dictionary key */
    sf_parser_bytes_init(
        &sfp,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=1");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
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

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      CU_ASSERT(0 == sf_parser_list(&sfp, &val));

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT((size_t)len == val.vec.len);
      CU_ASSERT(0 == memcmp(sbuf, val.vec.base, (size_t)len));
    }

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
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

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    for (i = 0; i < 1024; ++i) {
      CU_ASSERT(0 == sf_parser_list(&sfp, &val));
      CU_ASSERT(SF_TYPE_TOKEN == val.type);
      CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
      CU_ASSERT((size_t)len == key.len);
      CU_ASSERT(0 == memcmp(sbuf, key.base, (size_t)len));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
      CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));
    }

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large params */
    p = buf;

    memcpy(buf, "foo", sizeof("foo") - 1);

    p += sizeof("foo") - 1;

    for (i = 0; i < 1024; ++i) {
      len = snprintf((char *)p, (size_t)(buf + sizeof(buf) - p), ";a%d=1",
                     (int)i);
      p += len;
    }

    len = (int)(p - buf);

    sf_parser_bytes_len_init(&sfp, buf, (size_t)len);

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    for (i = 0; i < 1024; ++i) {
      len = snprintf((char *)sbuf, sizeof(sbuf), "a%d", (int)i);

      CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
      CU_ASSERT((size_t)len == key.len);
      CU_ASSERT(0 == memcmp(sbuf, key.base, (size_t)len));
      CU_ASSERT(SF_TYPE_INTEGER == val.type);
      CU_ASSERT(1 == val.integer);
    }

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large param key */
    sf_parser_bytes_init(
        &sfp,
        "foo;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
        "1");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large string */
    sf_parser_bytes_init(
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

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq(
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
        &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large escaped string */
    sf_parser_bytes_init(
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

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(val.flags & SF_VALUE_FLAG_ESCAPED_STRING);

    unescaped.base = buf;
    sf_unescape(&unescaped, &val.vec);

    CU_ASSERT(str_sf_vec_eq(
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
        &unescaped));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* large token */
    sf_parser_bytes_init(
        &sfp,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaa");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaa",
        &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }
}

void test_sf_parser_examples(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  sf_vec decoded;
  uint8_t buf[64];

  /* https://github.com/httpwg/structured-field-tests/blob/main/examples.json */

  {
    /* Foo-Example */
    sf_parser_bytes_init(&sfp, "2; foourl=\"https://foo.example.com/\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foourl", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(!(val.flags & SF_VALUE_FLAG_ESCAPED_STRING));
    CU_ASSERT(str_sf_vec_eq("https://foo.example.com/", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-StrListHeader */
    sf_parser_bytes_init(&sfp,
                         "\"foo\", \"bar\", \"It was the best of times.\"");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(!(val.flags & SF_VALUE_FLAG_ESCAPED_STRING));
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(!(val.flags & SF_VALUE_FLAG_ESCAPED_STRING));
    CU_ASSERT(str_sf_vec_eq("bar", &val.vec));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(!(val.flags & SF_VALUE_FLAG_ESCAPED_STRING));
    CU_ASSERT(str_sf_vec_eq("It was the best of times.", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-StrListListHeader */
    sf_parser_bytes_init(&sfp,
                         "(\"foo\" \"bar\"), (\"baz\"), (\"bat\" \"one\"), ()");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("bar", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("baz", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("bat", &val.vec));

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("one", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-ListListParam */
    sf_parser_bytes_init(&sfp,
                         "(\"foo\"; a=1;b=2);lvl=5, (\"bar\" \"baz\");lvl=1");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("foo", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("lvl", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("bar", &val.vec));

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("baz", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, &val));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("lvl", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-ParamListHeader */
    sf_parser_bytes_init(&sfp,
                         "abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w");

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("abc", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("cde_456", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(0 == sf_parser_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("ghi", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("jk", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(4 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("l", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("q", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("9", &val.vec));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("r", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("w", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_list(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-IntHeader */
    sf_parser_bytes_init(&sfp, "1; a; b=?0");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(0 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-DictHeader */
    sf_parser_bytes_init(&sfp, "en=\"Applepie\", da=:w4ZibGV0w6ZydGU=:");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("en", &key));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("Applepie", &val.vec));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("da", &key));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("w4ZibGV0w6ZydGU=", &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("\xc3\x86"
                            "blet\xc3\xa6"
                            "rte",
                            &decoded));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-DictHeader (boolean values) */
    sf_parser_bytes_init(&sfp, "a=?0, b, c; foo=bar");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(0 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foo", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("bar", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-DictListHeader */
    sf_parser_bytes_init(&sfp, "rating=1.5, feelings=(joy sadness)");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("rating", &key));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(15 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("feelings", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("joy", &val.vec));

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("sadness", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-MixDict */
    sf_parser_bytes_init(&sfp, "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("a", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("b", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(3 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("c", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(4 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("aa", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("bb", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("d", &key));
    CU_ASSERT(SF_TYPE_INNER_LIST == val.type);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);

    CU_ASSERT(0 == sf_parser_inner_list(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(6 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_inner_list(&sfp, NULL));

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("valid", &key));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-Hdr (dictionary on one line) */
    sf_parser_bytes_init(&sfp, "foo=1, bar=2");

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foo", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(1 == val.integer);

    CU_ASSERT(0 == sf_parser_dict(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("bar", &key));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(2 == val.integer);

    CU_ASSERT(SF_ERR_EOF == sf_parser_dict(&sfp, NULL, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-IntItemHeader */
    sf_parser_bytes_init(&sfp, "5");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-IntItemHeader (params) */
    sf_parser_bytes_init(&sfp, "5; foo=bar");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(5 == val.integer);

    CU_ASSERT(0 == sf_parser_param(&sfp, &key, &val));
    CU_ASSERT(str_sf_vec_eq("foo", &key));
    CU_ASSERT(SF_TYPE_TOKEN == val.type);
    CU_ASSERT(str_sf_vec_eq("bar", &val.vec));

    CU_ASSERT(SF_ERR_EOF == sf_parser_param(&sfp, NULL, NULL));

    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-IntegerHeader */
    sf_parser_bytes_init(&sfp, "42");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_INTEGER == val.type);
    CU_ASSERT(42 == val.integer);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-FloatHeader */
    sf_parser_bytes_init(&sfp, "4.5");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_DECIMAL == val.type);
    CU_ASSERT(45 == val.decimal.numer);
    CU_ASSERT(10 == val.decimal.denom);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-StringHeader */
    sf_parser_bytes_init(&sfp, "\"hello world\"");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_STRING == val.type);
    CU_ASSERT(str_sf_vec_eq("hello world", &val.vec));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-BinaryHdr */
    sf_parser_bytes_init(&sfp,
                         ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BYTESEQ == val.type);
    CU_ASSERT(str_sf_vec_eq("cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==",
                            &val.vec));

    decoded.base = buf;
    sf_base64decode(&decoded, &val.vec);

    CU_ASSERT(str_sf_vec_eq("pretend this is binary content.", &decoded));
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }

  {
    /* Example-BoolHdr */
    sf_parser_bytes_init(&sfp, "?1");

    CU_ASSERT(0 == sf_parser_item(&sfp, &val));
    CU_ASSERT(SF_TYPE_BOOLEAN == val.type);
    CU_ASSERT(1 == val.boolean);
    CU_ASSERT(SF_ERR_EOF == sf_parser_item(&sfp, NULL));

    sf_parser_bytes_free();
  }
}
