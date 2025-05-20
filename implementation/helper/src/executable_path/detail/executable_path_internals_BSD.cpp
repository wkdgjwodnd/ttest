//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#include <boost/predef.h>

#if (BOOST_OS_BSD)

#include <string>
#include <vector>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <boost/executable_path/detail/executable_path_internals.hpp>

#if (BOOST_OS_BSD_FREE)

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdlib.h>

namespace boost { namespace detail {

boost::filesystem::path executable_path_worker()
{
  typedef std::vector<char> char_vector;
  boost::filesystem::path ret;
  int mib[4]{0};
  size_t size;
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PATHNAME;
  mib[3] = -1;
  int result = sysctl(mib, 4, nullptr, &size, nullptr, 0);
  if (-1 == result)
  {
    return ret;
  }
  char_vector buf(size + 1, 0);
  result = sysctl(mib, 4, buf.data(), &size, nullptr, 0);
  if (-1 == result)
  {
    return ret;
  }
  std::string pathString(buf.data(), size);
  boost::system::error_code ec;
  ret = boost::filesystem::canonical(
    pathString, boost::filesystem::current_path(), ec);
  if (ec.value() != boost::system::errc::success)
  {
    ret.clear();
  }
  return ret;
}

}} // namespace namespace boost::detail

#elif (BOOST_OS_BSD_NET)

namespace boost { namespace detail {

boost::filesystem::path executable_path_worker()
{
  boost::filesystem::path ret;
  boost::system::error_code ec;
  auto linkPath = boost::filesystem::read_symlink("/proc/curproc/exe", ec);
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

#elif BOOST_OS_BSD_DRAGONFLY

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdlib.h>

namespace boost { namespace detail {

boost::filesystem::path executable_path_worker()
{
  boost::filesystem::path ret;
  boost::system::error_code ec;
  auto linkPath = boost::filesystem::read_symlink("/proc/curproc/file", ec);
  if (ec.value() != boost::system::errc::success)
  {
    int mib[4]{0};
    size_t size;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PATHNAME;
    mib[3] = -1;
    int result = sysctl(mib, 4, nullptr, &size, nullptr, 0);
    if (-1 != result)
    {
      char_vector buf(size + 1, 0);
      result = sysctl(mib, 4, buf.data(), &size, nullptr, 0);
      if (-1 != result)
      {
        std::string pathString(buf.data(), size);
        linkPath = pathString;
      }
    }
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

#endif
