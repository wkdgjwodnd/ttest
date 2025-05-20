// Copyright (C) 2019 Marco Iorio (Politecnico di Torino)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_CIPHER_UTILITIES_HPP
#define VSOMEIP_CIPHER_UTILITIES_HPP

#include <limits>
#include <string>
#include <openssl/crypto.h>

namespace vsomeip {

template<typename T>
struct zallocator {
public:
    typedef T value_type;
    typedef value_type *pointer;
    typedef const value_type *const_pointer;
    typedef value_type &reference;
    typedef const value_type &const_reference;
    typedef std::size_t size_type;
    typedef std::ptrdiff_t difference_type;

    pointer address(reference v) const { return &v; }

    const_pointer address(const_reference v) const { return &v; }

    pointer allocate(size_type n, const void *hint = nullptr) {
        (void) hint;
        if (n > std::numeric_limits<size_type>::max() / sizeof(T))
            throw std::bad_alloc();
        return static_cast<pointer> (::operator new(n * sizeof(value_type)));
    }

    void deallocate(pointer p, size_type n) {
        OPENSSL_cleanse(p, n * sizeof(T));
        ::operator delete(p);
    }

    size_type max_size() const {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template<typename U>
    struct rebind {
        typedef zallocator<U> other;
    };

    void construct(pointer ptr, const T &val) {
        new(static_cast<T *>(ptr)) T(val);
    }

    void destroy(pointer ptr) {
        static_cast<T *>(ptr)->~T();
    }

#if __cpluplus >= 201103L
    template<typename U, typename... Args>
    void construct (U* ptr, Args&&  ... args) {
        ::new (static_cast<void*> (ptr) ) U (std::forward<Args> (args)...);
    }

    template<typename U>
    void destroy(U* ptr) {
        ptr->~U();
    }
#endif
};

std::string get_openssl_errors(const std::string &message);

} // namespace vsomeip

#endif //VSOMEIP_CIPHER_UTILITIES_HPP
