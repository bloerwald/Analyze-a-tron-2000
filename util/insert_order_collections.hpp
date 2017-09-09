#pragma once

#include <exception>
#include <set>
#include <vector>

namespace util
{
  template<typename T>
    struct insert_order_set : private std::vector<T>
  {
    template<typename... U>
      void emplace (U... u)
    {
      if (_seen.emplace (u...).second)
      {
        this->emplace_back (u...);
      }
    }

    using std::vector<T>::begin;
    using std::vector<T>::end;

  private:
    std::set<T> _seen;
  };

  template<typename Key, typename T>
    struct insert_order_map : private std::vector<std::pair<Key, T>>
  {
    T& operator[] (Key key)
    {
      if (_seen.emplace (key).second)
      {
        this->emplace_back (key, T{});
        return this->back().second;
      }
      else
      {
        for (auto& elem : *this)
        {
          if (elem.first == key)
          {
            return elem.second;
          }
        }
        throw std::logic_error ("unreachable");
      }
    }

    using std::vector<std::pair<Key, T>>::begin;
    using std::vector<std::pair<Key, T>>::end;

  private:
    std::set<Key> _seen;
  };
}
