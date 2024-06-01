// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
//
// http://code.google.com/p/cityhash/
//
// This file provides a few functions for hashing strings.  All of them are
// high-quality functions in the sense that they pass standard tests such
// as Austin Appleby's SMHasher.  They are also fast.
//
// For 64-bit x86 code, on short strings, we don't know of anything faster than
// CityHash64 that is of comparable quality.  We believe our nearest competitor
// is Murmur3.  For 64-bit x86 code, CityHash64 is an excellent choice for hash
// tables and most other hashing (excluding cryptography).
//
// For 64-bit x86 code, on long strings, the picture is more complicated.
// On many recent Intel CPUs, such as Nehalem, Westmere, Sandy Bridge, etc.,
// CityHashCrc128 appears to be faster than all competitors of comparable
// quality.  CityHash128 is also good but not quite as fast.  We believe our
// nearest competitor is Bob Jenkins' Spooky.  We don't have great data for
// other 64-bit CPUs, but for long strings we know that Spooky is slightly
// faster than CityHash on some relatively recent AMD x86-64 CPUs, for example.
// Note that CityHashCrc128 is declared in citycrc.h.
//
// For 32-bit x86 code, we don't know of anything faster than CityHash32 that
// is of comparable quality.  We believe our nearest competitor is Murmur3A.
// (On 64-bit CPUs, it is typically faster to use the other CityHash variants.)
//
// Functions in the CityHash family are not suitable for cryptography.
//
// Please see CityHash's README file for more details on our performance
// measurements and so on.
//
// WARNING: This code has been only lightly tested on big-endian platforms!
// It is known to work well on little-endian platforms that have a small penalty
// for unaligned reads, such as current Intel and AMD moderate-to-high-end CPUs.
// It should work on all 32-bit and 64-bit platforms that allow unaligned reads;
// bug reports are welcome.
//
// By the way, for some hash functions, given strings a and b, the hash
// of a+b is easily derived from the hashes of a and b.  This property
// doesn't hold for any hash functions in this file.

//////////////////////////////////////////////
//	city.hpp								//
//											//
//	Author: Geoff Pike and Jyrki Alakuijala	//
//	Edited: Francisco Julio Ruiz Fernandez	//
//	Edited: llanyro							//
//////////////////////////////////////////////

#ifndef LLCPP_CITY_HASH_HPP_
#define LLCPP_CITY_HASH_HPP_

#include <llanylib/cityhash.hpp>

namespace llcpp {
namespace city {

namespace traits = llcpp::meta::traits;
namespace hash = llcpp::meta::hash;

using OptionalHash32 = std::optional<ui32>;

#pragma region Hash32
// Hash function for a byte array.  Most useful in 32-bit binaries.
LL_SHARED_LIB __LL_NODISCARD__ OptionalHash32 CityHash32(ll_string_t buf, len_t len);

#pragma endregion
#pragma region Hash64

// Hash function for a byte array.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64(ll_string_t buf, len_t len);

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64WithSeed(ll_string_t buf, const len_t len, const ui64 seed);

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64WithSeeds(ll_string_t buf, const len_t len, const ui64 seed0, const ui64 seed1);

#pragma region Objects
template<class U, class W = traits::template_types<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64(typename W::cinput data) __LL_EXCEPT__ {
	return city::CityHash64(reinterpret_cast<ll_string_t>(&data), sizeof(U));
}
template<class U, class W = traits::template_types<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeed(typename W::cinput data, const ui64 seed) __LL_EXCEPT__ {
	return city::CityHash64WithSeed(reinterpret_cast<ll_string_t>(&data), sizeof(U), seed);
}
template<class U, class W = traits::template_types<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeeds(typename W::cinput data, const ui64 seed0, const ui64 seed1) __LL_EXCEPT__ {
	return city::CityHash64WithSeeds(reinterpret_cast<ll_string_t>(&data), sizeof(U), seed0, seed1);
}

#pragma endregion
#pragma region Array
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64(const T(&data)[N]) __LL_EXCEPT__ {
	return city::CityHash64(reinterpret_cast<ll_string_t>(data), sizeof(T) * N);
}
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeed(const T(&data)[N], const ui64 seed) __LL_EXCEPT__ {
	return city::CityHash64WithSeed(reinterpret_cast<ll_string_t>(data), sizeof(T) * N, seed);
}
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeeds(const T(&data)[N], const ui64 seed0, const ui64 seed1) __LL_EXCEPT__ {
	return city::CityHash64WithSeeds(reinterpret_cast<ll_string_t>(data), sizeof(T) * N, seed0, seed1);
}

#pragma endregion

#pragma endregion
#pragma region Hash128
// Hash function for a byte array.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash128 CityHash128(ll_string_t s, len_t len);

// Hash function for a byte array.  For convenience, a 128-bit seed is also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash128 CityHash128WithSeed(ll_string_t s, len_t len, const hash::Hash128& seed);

#pragma endregion

} // namespace city
} // namespace llcpp

#endif  // LLCPP_CITY_HASH_HPP_
