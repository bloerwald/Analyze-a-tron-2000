#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

namespace {
  std::array<std::uint32_t, 16> const s_hashtable {
    0x486E26EE, 0xDCAA16B3, 0xE1918EEF, 0x202DAFDB,
    0x341C7DC7, 0x1C365303, 0x40EF2D37, 0x65FD5E49,
    0xD6057177, 0x904ECE93, 0x1C38024F, 0x98FD323B,
    0xE3061AE7, 0xA39B0FA1, 0x9797F25F, 0xE4444563,
  };

  std::uint32_t hash (std::string const& s)
  {
    std::uint32_t v (0x7fed7fed);
    std::uint32_t x (0xeeeeeeee);
    for (auto const& cc : s)
    {
      auto c (*reinterpret_cast<unsigned char const*> (&cc));
      v = (x + v) ^ (s_hashtable[(c >> 4) & 0xf] - s_hashtable[c & 0xf]);
      x = c + x * 33 + v + 3;
    }
    return v;
  }
}

int main(int argc, char** argv) {
  for (int arg (1); arg < argc; ++arg) {
    std::string name (argv[arg]);
    std::transform ( name.begin(), name.end(), name.begin()
                   , [] (int c) { return std::toupper (c); }
                   );
    printf ("%08x %s\n", hash (name), name.c_str());
  }

  return 0;
}
