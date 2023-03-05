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

static void print_key(const char *prefix, const sf_vec *key) {
  printf("%s: %.*s\n", prefix, (int)key->len, key->base);
}

static void print_value(const char *prefix, const sf_value *val) {
  uint8_t *buf;
  sf_vec decoded;

  switch (val->type) {
  case SF_VALUE_TYPE_BOOLEAN:
    printf("%s: %s\n", prefix, val->boolean ? "true" : "false");

    break;
  case SF_VALUE_TYPE_INTEGER:
    printf("%s: %" PRId64 "\n", prefix, val->integer);

    break;
  case SF_VALUE_TYPE_DECIMAL:
    printf("%s: %.03f\n", prefix,
           (double)val->decimal.numer / (double)val->decimal.denom);

    break;
  case SF_VALUE_TYPE_STRING:
    if (!(val->flags & SF_VALUE_FLAG_ESCAPED_STRING)) {
      printf("%s: (string) %.*s\n", prefix, (int)val->vec.len, val->vec.base);

      break;
    }

    buf = malloc(val->vec.len);
    decoded.base = buf;
    sf_unescape(&decoded, &val->vec);

    printf("%s: (string) %.*s\n", prefix, (int)decoded.len, decoded.base);

    free(buf);

    break;
  case SF_VALUE_TYPE_TOKEN:
    printf("%s: (token) %.*s\n", prefix, (int)val->vec.len, val->vec.base);

    break;
  case SF_VALUE_TYPE_BYTESEQ:
    buf = malloc(val->vec.len);
    decoded.base = buf;
    sf_base64decode(&decoded, &val->vec);

    printf("%s: (byteseq) %.*s\n", prefix, (int)decoded.len, decoded.base);

    free(buf);

    break;
  case SF_VALUE_TYPE_INNER_LIST:
    printf("%s: (inner list)\n", prefix);

    break;
  default:
    assert(0);
  }
}

static void example_dictionary(void) {
  static const uint8_t s[] = "a=(1 2 3;b=\"foo\");c;d=1, e=1.001";
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  int rv;

  printf("# example dictionary\n");

  {
    printf("## Iterate dictionary keys\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_dict(&sfp, &key, NULL);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
    }
  }

  {
    printf("## Iterate dictionary values\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
      print_value("value", &val);
    }
  }

  {
    printf("## Read inner list\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      if (val.type == SF_VALUE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sf_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SF_ERR_EOF == rv);

            break;
          }

          print_value("value", &val);
        }
      }
    }
  }

  {
    printf("## Read parameters\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_key("key", &key);
      print_value("value", &val);

      for (;;) {
        rv = sf_parser_param(&sfp, &key, &val);
        if (rv != 0) {
          assert(SF_ERR_EOF == rv);

          break;
        }

        print_key("param-key", &key);
        print_value("param-value", &val);
      }
    }
  }

  {
    printf("## Read parameters of items in inner list\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_dict(&sfp, &key, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      if (val.type == SF_VALUE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sf_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SF_ERR_EOF == rv);

            break;
          }

          for (;;) {
            rv = sf_parser_param(&sfp, &key, &val);
            if (rv != 0) {
              assert(SF_ERR_EOF == rv);

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
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  int rv;

  printf("# example list\n");

  {
    printf("## Iterate list values\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);
    }
  }

  {
    printf("## Read inner list\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      if (val.type == SF_VALUE_TYPE_INNER_LIST) {
        for (;;) {
          rv = sf_parser_inner_list(&sfp, &val);
          if (rv != 0) {
            assert(SF_ERR_EOF == rv);

            break;
          }

          print_value("value", &val);
        }
      }
    }
  }

  {
    printf("## Read parameters\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    for (;;) {
      rv = sf_parser_list(&sfp, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);

      for (;;) {
        rv = sf_parser_param(&sfp, &key, &val);
        if (rv != 0) {
          assert(SF_ERR_EOF == rv);

          break;
        }

        print_key("param-key", &key);
        print_value("param-value", &val);
      }
    }
  }
}

static void example_item(void) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;
  int rv;

  printf("# example item\n");

  {
    static const uint8_t s[] = "?1";

    printf("## Read boolean\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "1000000009";

    printf("## Read integer\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "1000000009.123";

    printf("## Read decimal\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "\"foo\"";

    printf("## Read string\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "foo";

    printf("## Read token\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = ":Zm9v:";

    printf("## Read byteseq\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "(1 2 3)";

    printf("## Read inner list\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    print_value("value", &val);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "(1 2 3)";

    printf("## Read each value in inner list\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);
    assert(SF_VALUE_TYPE_INNER_LIST == val.type);

    for (;;) {
      rv = sf_parser_inner_list(&sfp, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_value("value", &val);
    }

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "f;g=1;h=2";

    printf("## Read parameters\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    for (;;) {
      rv = sf_parser_param(&sfp, &key, &val);
      if (rv != 0) {
        assert(SF_ERR_EOF == rv);

        break;
      }

      print_key("param-key", &key);
      print_value("param-value", &val);
    }

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_EOF == rv);
  }

  {
    static const uint8_t s[] = "foo bar";
    printf("## Trailing garbage causes parse error\n");

    sf_parser_init(&sfp, s, sizeof(s) - 1);

    rv = sf_parser_item(&sfp, &val);

    assert(0 == rv);

    rv = sf_parser_item(&sfp, NULL);

    assert(SF_ERR_PARSE_ERROR == rv);
  }
}

int main(void) {
  example_dictionary();
  example_list();
  example_item();

  return 0;
}
