//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#include <boost/predef.h>

#if (BOOST_OS_ANDROID || BOOST_OS_HPUX || BOOST_OS_LINUX || BOOST_OS_UNIX)

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <boost/executable_path/detail/executable_path_internals.hpp>

namespace boost { namespace detail {

boost::filesystem::path executable_path_worker()
{
  boost::filesystem::path ret;
  boost::system::error_code ec;
  auto linkPath = boost::filesystem::read_symlink("/proc/self/exe", ec);
  if (ec.value() != boost::system::errc::success)
  {
    return ret;
  }
  ret = boost::filesystem::canonical(
    linkPath, boost::filesystem::current_path(), ec);
  if (ec.value() != boost::system::errc::success)
  {
    ret.clear();
  }
  return ret;
}

}} // namespace boost::detail

#endif
