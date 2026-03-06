#pragma once

#include <sys/system_properties.h>

#include <algorithm>
#include <cstddef>
#include <string>

/**
 * @file utils.h
 * @brief Miscellaneous utility functions and templates for the native library.
 */

namespace vector::native {

/**
 * @brief Returns the number of elements in a statically-allocated C-style array.
 *
 * This is a compile-time constant.
 * Attempting to use this on a pointer will result in a compilation error,
 * preventing common mistakes.
 *
 * @tparam T The type of the array elements.
 * @tparam N The size of the array.
 * @param arr A reference to the array.
 * @return The number of elements in the array.
 */
template <typename T, size_t N>
[[nodiscard]] constexpr inline size_t ArraySize(T (&)[N]) {
    return N;
}

}  // namespace vector::native
