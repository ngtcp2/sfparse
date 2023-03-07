#include "sfparse.h"

namespace {
void asDict(const uint8_t *data, size_t size) {
  sf_parser sfp;
  sf_vec key;
  sf_value val;

  sf_parser_init(&sfp, data, size);

  for (;;) {
    auto rv = sf_parser_dict(&sfp, &key, &val);
    if (rv != 0) {
      break;
    }
  }
}
} // namespace

namespace {
void asList(const uint8_t *data, size_t size) {
  sf_parser sfp;
  sf_value val;

  sf_parser_init(&sfp, data, size);

  for (;;) {
    auto rv = sf_parser_list(&sfp, &val);
    if (rv != 0) {
      break;
    }
  }
}
} // namespace

namespace {
void asItem(const uint8_t *data, size_t size) {
  sf_parser sfp;
  sf_value val;

  sf_parser_init(&sfp, data, size);

  auto rv = sf_parser_item(&sfp, &val);
  if (rv != 0) {
    return;
  }

  sf_parser_item(&sfp, &val);
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  asDict(data, size);
  asList(data, size);
  asItem(data, size);

  return 0;
}
