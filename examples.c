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
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "sfparse.h"

static void print_key(const char *prefix, const sfparse_vec *key) {
  printf("%s: %.*s\n", prefix, (int)key->len, key->base);
}

static void print_value(const char *prefix, const sfparse_value *val) {
  uint8_t *buf;
  sfparse_vec decoded;

  switch (val->type) {
  case SFPARSE_TYPE_BOOLEAN:
    printf("%s: %s\n", prefix, val->boolean ? "true" : "false");

    break;
  case SFPARSE_TYPE_INTEGER:
    printf("%s: %" PRId64 "\n", prefix, val->integer);

    break;
  case SFPARSE_TYPE_DECIMAL:
    printf("%s: %.03f\n", prefix,
           (double)val->decimal.numer / (double)val->decimal.denom);

    break;
  case SFPARSE_TYPE_STRING:
    if (!(val->flags & SFPARSE_VALUE_FLAG_ESCAPED_STRING)) {
      printf("%s: (string) %.*s\n", prefix, (int)val->vec.len, val->vec.base);

      break;
    }

    buf = malloc(val->vec.len);
    decoded.base = buf;
    sfparse_unescape(&decoded, &val->vec);

    printf("%s: (string) %.*s\n", prefix, (int)decoded.len, decoded.base);

    free(buf);

    break;
  case SFPARSE_TYPE_TOKEN:
    printf("%s: (token) %.*s\n", prefix, (int)val->vec.len, val->vec.base);

    break;
  case SFPARSE_TYPE_BYTESEQ:
    buf = malloc(val->vec.len);
    decoded.base = buf;
    sfparse_base64decode(&decoded, &val->vec);

    printf("%s: (byteseq) %.*s\n", prefix, (int)decoded.len, decoded.base);

    free(buf);

    break;
  case SFPARSE_TYPE_INNER_LIST:
    printf("%s: (inner list)\n", prefix);

    break;
  case SFPARSE_TYPE_DATE:
    printf("%s: (date) %" PRId64 "\n", prefix, val->integer);

    break;
  case SFPARSE_TYPE_DISPSTRING:
    buf = malloc(val->vec.len);
    decoded.base = buf;
    sfparse_pctdecode(&decoded, &val->vec);

    printf("%s: (dispstring) %.*s\n", prefix, (int)decoded.len, decoded.base);

    free(buf);

    break;
  default:
    assert(0);
  }
}

static void example_dictionary(void) {
  static const uint8_t s[] = "a=(1 2 3;b=\"foo\");c;d=1, e=1.001";
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  int rv;

  printf("# example dictionary\n");

  {
    printf("## Iterate dictionary keys\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_dict(&sfp, &key, NULL);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
    }
  }

  {
    printf("## Iterate dictionary values\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
      print_value("value", &val);
    }
  }

  {
    printf("## Read inner list\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      if (val.type == SFPARSE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sfparse_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SFPARSE_ERR_EOF == rv);

            break;
          }

          print_value("value", &val);
        }
      }
    }
  }

  {
    printf("## Read parameters\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
      print_value("value", &val);

      for (;;) {
        rv = sfparse_parser_param(&sfp, &key, &val);
        if (rv != 0) {
          assert(SFPARSE_ERR_EOF == rv);

          break;
        }

        print_key("param-key", &key);
        print_value("param-value", &val);
      }
    }
  }

  {
    printf("## Read parameters of items in inner list\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      if (val.type == SFPARSE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sfparse_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SFPARSE_ERR_EOF == rv);

            break;
          }

          for (;;) {
            rv = sfparse_parser_param(&sfp, &key, &val);
            if (rv != 0) {
              assert(SFPARSE_ERR_EOF == rv);

              break;
            }

            print_key("param-key", &key);
            print_value("param-value", &val);
          }
        }
      }
    }
  }
}

static void example_list(void) {
  static const uint8_t s[] = "(1 2 3;b=\"foo\"), bar, baz;f=:aGVsbG8=:";
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  int rv;

  printf("# example list\n");

  {
    printf("## Iterate list values\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);
    }
  }

  {
    printf("## Read inner list\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      if (val.type == SFPARSE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sfparse_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SFPARSE_ERR_EOF == rv);

            break;
          }

          print_value("value", &val);
        }
      }
    }
  }

  {
    printf("## Read parameters\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sfparse_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);

      for (;;) {
        rv = sfparse_parser_param(&sfp, &key, &val);
        if (rv != 0) {
          assert(SFPARSE_ERR_EOF == rv);

          break;
        }

        print_key("param-key", &key);
        print_value("param-value", &val);
      }
    }
  }
}

static void example_item(void) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  int rv;

  printf("# example item\n");

  {
    static const uint8_t s[] = "?1";

    printf("## Read boolean\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "1000000009";

    printf("## Read integer\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "1000000009.123";

    printf("## Read decimal\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "\"foo\"";

    printf("## Read string\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "foo";

    printf("## Read token\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = ":Zm9v:";

    printf("## Read byteseq\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "@1659578233";

    printf("## Read date\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] =
      "%\"This is intended for display to %C3%BCsers.\"";

    printf("## Read dispstring\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "(1 2 3)";

    printf("## Read inner list\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "(1 2 3)";

    printf("## Read each value in inner list\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);
    assert(SFPARSE_TYPE_INNER_LIST == val.type);

    for (;;) {
      rv = sfparse_parser_inner_list(&sfp, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);
    }

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "f;g=1;h=2";

    printf("## Read parameters\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    for (;;) {
      rv = sfparse_parser_param(&sfp, &key, &val);
      if (rv != 0) {
        assert(SFPARSE_ERR_EOF == rv);

        break;
      }

      print_key("param-key", &key);
      print_value("param-value", &val);
    }

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "foo bar";
    printf("## Trailing garbage causes parse error\n");

    sfparse_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sfparse_parser_item(&sfp, &val);

    assert(0 == rv);

    rv = sfparse_parser_item(&sfp, NULL);

    assert(SFPARSE_ERR_PARSE == rv);
  }
}

typedef struct rfc9218_priority {
  int u, i;
} rfc9218_priority;

static int parse_rfc9218_priority(rfc9218_priority *pri, const uint8_t *data,
                                  size_t datalen) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;
  int rv;

  sfparse_parser_init(&sfp, data, datalen);

  for (;;) {
    rv = sfparse_parser_dict(&sfp, &key, &val);
    if (rv != 0) {
      if (rv == SFPARSE_ERR_PARSE) {
        return -1;
      }

      return 0;
    }

    if (key.len != 1) {
      continue;
    }

    switch (key.base[0]) {
    case 'u':
      if (val.type != SFPARSE_TYPE_INTEGER) {
        return -1;
      }

      if (val.integer < 0 || 7 < val.integer) {
        return -1;
      }

      pri->u = (int)val.integer;

      break;
    case 'i':
      if (val.type != SFPARSE_TYPE_BOOLEAN) {
        return -1;
      }

      pri->i = val.boolean;

      break;
    }
  }
}

static void example_rfc9218_priority(void) {
  static const uint8_t s[] = "u=5,i";
  rfc9218_priority pri = {0};

  printf("# RFC 9218 priority\n");

  if (parse_rfc9218_priority(&pri, s, sizeof(s) - 1) == 0) {
    printf("u=%d i=%d\n", pri.u, pri.i);
  }
}

int main(void) {
  example_dictionary();
  example_list();
  example_item();
  example_rfc9218_priority();

  return 0;
}
