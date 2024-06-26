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
#include <llanylib/hash_tools.hpp>

namespace llcpp {
namespace city {

namespace traits = llcpp::meta::traits;
namespace hash = llcpp::meta::hash;

#pragma region Hash32
// Hash function for a byte array.  Most useful in 32-bit binaries.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash32 CityHash32(ll_string_t buf, len_t len) noexcept;

#pragma endregion
#pragma region Hash64
// Hash function for a byte array.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(ll_string_t buf, len_t len) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(ll_wstring_t str, len_t size) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const std::string& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const std::wstring& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const meta::StrPair& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const meta::wStrPair& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const meta::Str& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const meta::wStr& str) noexcept;
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64(const hash::Hash64& h) noexcept;

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64WithSeed(ll_string_t buf, const len_t len, const ui64 seed) noexcept;

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash64 CityHash64WithSeeds(ll_string_t buf, const len_t len, const ui64 seed0, const ui64 seed1) noexcept;

#pragma region Objects
template<class U, class W = traits::cinput<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64(W data) noexcept {
	return city::CityHash64(reinterpret_cast<ll_string_t>(&data), sizeof(U));
}
template<class U, class W = traits::cinput<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeed(W data, const ui64 seed) noexcept {
	return city::CityHash64WithSeed(reinterpret_cast<ll_string_t>(&data), sizeof(U), seed);
}
template<class U, class W = traits::cinput<U>>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeeds(W data, const ui64 seed0, const ui64 seed1) noexcept {
	return city::CityHash64WithSeeds(reinterpret_cast<ll_string_t>(&data), sizeof(U), seed0, seed1);
}

#pragma endregion
#pragma region Array
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64(const T(&data)[N]) noexcept {
	return city::CityHash64(reinterpret_cast<ll_string_t>(data), sizeof(T) * N);
}
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeed(const T(&data)[N], const ui64 seed) noexcept {
	return city::CityHash64WithSeed(reinterpret_cast<ll_string_t>(data), sizeof(T) * N, seed);
}
template<class T, len_t N>
__LL_NODISCARD__ __LL_INLINE__ hash::OptionalHash64 CityHash64WithSeeds(const T(&data)[N], const ui64 seed0, const ui64 seed1) noexcept {
	return city::CityHash64WithSeeds(reinterpret_cast<ll_string_t>(data), sizeof(T) * N, seed0, seed1);
}

#pragma endregion

#pragma endregion
#pragma region Hash128
// Hash function for a byte array.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash128 CityHash128(ll_string_t s, len_t len) noexcept;

// Hash function for a byte array.  For convenience, a 128-bit seed is also
// hashed into the result.
__LL_NODISCARD__ LL_SHARED_LIB  hash::OptionalHash128 CityHash128WithSeed(ll_string_t s, len_t len, const hash::Hash128& seed) noexcept;

#pragma endregion

namespace __internal__ {
__LL_NODISCARD__ constexpr hash::OptionalHash64 empty(const void*, const meta::StrTypeid&) noexcept {
	return hash::INVALID_HASH64;
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 empty(const void*, const meta::wStrTypeid&) noexcept {
	return hash::INVALID_HASH64;
}

} // namespace __internal__

__LL_VAR_INLINE__ constexpr hash::Hash64Function CITYHASH_Hash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::wHash64Function CITYHASH_wHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::StringPairHash64Function CITYHASH_StringPairHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::wStringPairHash64Function CITYHASH_wStringPairHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::StrPairHash64Function CITYHASH_StrPairHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::wStrPairHash64Function CITYHASH_wStrPairHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::StrHash64Function CITYHASH_StrHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::wStrHash64Function CITYHASH_wStrHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::RecursiveHash64Function CITYHASH_RecursiveHash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::StrTypeidHash64Function CITYHASH_StrTypeidHash64Function = __internal__::empty;
__LL_VAR_INLINE__ constexpr hash::wStrTypeidHash64Function CITYHASH_wStrTypeidHash64Function = __internal__::empty;

__LL_VAR_INLINE__ constexpr hash::Hash64FunctionPack CITYHASH_FUNCTION_PACK = {
	CITYHASH_Hash64Function,
	CITYHASH_wHash64Function,
	CITYHASH_StringPairHash64Function,
	CITYHASH_wStringPairHash64Function,
	CITYHASH_StrPairHash64Function,
	CITYHASH_wStrPairHash64Function,
	CITYHASH_StrHash64Function,
	CITYHASH_wStrHash64Function,
	CITYHASH_RecursiveHash64Function,
	CITYHASH_StrTypeidHash64Function,
	CITYHASH_wStrTypeidHash64Function
};

__LL_VAR_INLINE__ constexpr hash::HashTool CITYHASH_TOOLS = hash::HashTool<>(CITYHASH_FUNCTION_PACK);

} // namespace city
} // namespace llcpp

#endif  // LLCPP_CITY_HASH_HPP_
