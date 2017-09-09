#pragma once

#include <initializer_list>
#include <string>

namespace util
{
  bool has_suffix (std::string const& string, std::string const& suffix);
  bool has_suffix (std::string const& string, std::initializer_list<std::string> suffixes);
}
