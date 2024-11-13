#include "sfparse.h"

namespace {
void asDict(const uint8_t *data, size_t size) {
  sfparse_parser sfp;
  sfparse_vec key;
  sfparse_value val;

  sfparse_parser_init(&sfp, data, size);

  for (;;) {
    auto rv = sfparse_parser_dict(&sfp, &key, &val);
    if (rv != 0) {
      break;
    }
  }
}
} // namespace

namespace {
void asList(const uint8_t *data, size_t size) {
  sfparse_parser sfp;
  sfparse_value val;

  sfparse_parser_init(&sfp, data, size);

  for (;;) {
    auto rv = sfparse_parser_list(&sfp, &val);
    if (rv != 0) {
      break;
    }
  }
}
} // namespace

namespace {
void asItem(const uint8_t *data, size_t size) {
  sfparse_parser sfp;
  sfparse_value val;

  sfparse_parser_init(&sfp, data, size);

  auto rv = sfparse_parser_item(&sfp, &val);
  if (rv != 0) {
    return;
  }

  sfparse_parser_item(&sfp, &val);
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  asDict(data, size);
  asList(data, size);
  asItem(data, size);

  return 0;
}
