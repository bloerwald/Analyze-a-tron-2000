#include "file.hpp"

#include <stdexcept>

namespace util
{
  file_t::file_t (std::string const& filename)
    : handle (fopen (filename.c_str(), "rb+"))
  {
    if (!handle)
    {
      throw std::runtime_error ("failed to open file " + filename);
    }
    fseek (handle, 0, SEEK_END);
    data.resize (ftell (handle));
    fseek (handle, 0, SEEK_SET);
    fread (data.data(), data.size(), 1, handle);
  }
  file_t::~file_t()
  {
    fclose (handle);
  }
  void const* file_t::end() const
  {
    return data.data() + data.size();
  }
  std::vector<uint8_t> data;
  FILE* handle;
}
