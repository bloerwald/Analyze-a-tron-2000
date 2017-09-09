#include "iffchunk.hpp"

namespace util
{
  iffchunk const* iffchunk::next() const
  {
    return sub (size);
  }
  iffchunk const* iffchunk::sub (std::size_t offset) const
  {
    return reinterpret_cast<iffchunk const*> (&data[offset]);
  }

  uint32_t reversed (uint32_t magic)
  {
    return (((magic & 0xFF000000) >> 24) <<  0)
         | (((magic & 0x00FF0000) >> 16) <<  8)
         | (((magic & 0x0000FF00) >>  8) << 16)
         | (((magic & 0x000000FF) >>  0) << 24);
  }
  std::string readable_magic (uint32_t magic, bool flipped)
  {
    auto const magic_c (reinterpret_cast<char const*> (&magic));
    return flipped ? readable_magic (reversed (magic), false)
                   : std::string() + magic_c[0] + magic_c[1] + magic_c[2] + magic_c[3]
                   ;
  }
}
