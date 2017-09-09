#include "string.hpp"

namespace util
{
  bool has_suffix (std::string const& string, std::string const& suffix)
  {
    return suffix.size() <= string.size() 
      && string.substr (string.size() - suffix.size()) == suffix;
  }

  bool has_suffix (std::string const& string, std::initializer_list<std::string> suffixes)
  {
    for (auto const& entry : suffixes)
    {
      if (has_suffix (string, entry))
      {
        return true;
      }
    }

    return false;
  }
}
