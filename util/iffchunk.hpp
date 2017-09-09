#pragma once

#include <cstdint>
#include <string>

namespace util
{
  struct iffchunk
  {
    uint32_t magic;
    uint32_t size;
    uint8_t data[0];

    iffchunk const* next() const;
    iffchunk const* sub (std::size_t offset) const;
  };

  uint32_t reversed (uint32_t magic);
  std::string readable_magic (uint32_t magic, bool flipped);
}
