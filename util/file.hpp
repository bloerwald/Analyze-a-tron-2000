#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace util
{
  struct file_t
  {
    file_t (std::string const& filename);
    ~file_t();

    void const* end() const;

    std::vector<uint8_t> data;
    FILE* handle;
  };
}
