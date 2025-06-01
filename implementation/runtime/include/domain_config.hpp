#include <array>
#include <cstdint>
#include <stdexcept>   // ← 추가

namespace vsomeip {
    using byte_t = std::uint8_t;

    // 📌 Central place to add / reorder domain numbers
    constexpr std::array<byte_t,4> DOMAIN_TABLE{10,20,30,40};

    inline constexpr std::size_t domain_index(byte_t dn) {
        for(std::size_t i = 0; i < DOMAIN_TABLE.size(); ++i)
            if (DOMAIN_TABLE[i] == dn) return i;
        throw std::out_of_range("invalid domain number");
    }
}