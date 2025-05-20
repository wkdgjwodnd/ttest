//
// Copyright (C) 2011-2017 Ben Key
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_boost or copy at
// http://www.boost.org/LICENSE_boost)
//

#ifndef BOOST_EXECUTABLE_PATH_HPP_
#define BOOST_EXECUTABLE_PATH_HPP_

#pragma once

#include <string>

namespace boost {
std::string executable_path(const char* argv0);
std::wstring executable_path(const wchar_t* argv0);
}

#endif // BOOST_EXECUTABLE_PATH_HPP_
