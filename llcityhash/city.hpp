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
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash32 CityHash32(ll_string_t buf, len_t len) __LL_EXCEPT__;

#pragma endregion
#pragma region Hash64
// Hash function for a byte array.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64(ll_string_t buf, len_t len) __LL_EXCEPT__;

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64WithSeed(ll_string_t buf, const len_t len, const ui64 seed) __LL_EXCEPT__;

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash64 CityHash64WithSeeds(ll_string_t buf, const len_t len, const ui64 seed0, const ui64 seed1) __LL_EXCEPT__;

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
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash128 CityHash128(ll_string_t s, len_t len) __LL_EXCEPT__;

// Hash function for a byte array.  For convenience, a 128-bit seed is also
// hashed into the result.
LL_SHARED_LIB __LL_NODISCARD__ hash::OptionalHash128 CityHash128WithSeed(ll_string_t s, len_t len, const hash::Hash128& seed) __LL_EXCEPT__;

#pragma endregion

namespace __internal__ {
__LL_NODISCARD__ constexpr hash::OptionalHash64 hash_wstr(ll_wstring_t str, len_t size) __LL_EXCEPT__ {
	constexpr len_t PARSER_BUFFER_SIZE = 512;
	ll_char_t buffer[PARSER_BUFFER_SIZE]{};
	len_t buffer_len = sizeof(ll_wchar_t) * size;
	if (buffer_len > PARSER_BUFFER_SIZE) return hash::INVALID_HASH64;

	ll_char_t* i = buffer;
	for (ll_wstring_t data_end = str + size; str < data_end; ++str)
		hash::basic_type_hash::conversor<ll_wchar_t>(i, *str);
	return llcpp::city::CityHash64(buffer, buffer_len);
}
__LL_NODISCARD__ hash::OptionalHash64 hash_str(const meta::StrPair& str) __LL_EXCEPT__ {
	return city::CityHash64(str.begin(), str.len());
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 hash_wstr(const meta::wStrPair& str) __LL_EXCEPT__ {
	return hash_wstr(str.begin(), str.len());
}
__LL_NODISCARD__ hash::OptionalHash64 hash_str(const meta::Str& str) __LL_EXCEPT__ {
	return city::CityHash64(str.begin(), str.len());
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 hash_wstr(const meta::wStr& str) __LL_EXCEPT__ {
	return hash_wstr(str.begin(), str.len());
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 hash(const hash::Hash64& h) __LL_EXCEPT__ {
	return hash::basic_type_hash::hashValue<ui64>(h.get(), llcpp::city::CityHash64);
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 empty(const void*, const meta::StrTypeid&) __LL_EXCEPT__ {
	return hash::INVALID_HASH64;
}
__LL_NODISCARD__ constexpr hash::OptionalHash64 empty(const void*, const meta::wStrTypeid&) __LL_EXCEPT__ {
	return hash::INVALID_HASH64;
}

} // namespace __internal__

__LL_VAR_INLINE__ constexpr hash::Hash64Function CITYHASH_Hash64Function = city::CityHash64;
__LL_VAR_INLINE__ constexpr hash::wHash64Function CITYHASH_wHash64Function = __internal__::hash_wstr;
__LL_VAR_INLINE__ constexpr hash::StrPairHash64Function CITYHASH_StrPairHash64Function = __internal__::hash_str;
__LL_VAR_INLINE__ constexpr hash::wStrPairHash64Function CITYHASH_wStrPairHash64Function = __internal__::hash_wstr;
__LL_VAR_INLINE__ constexpr hash::StrHash64Function CITYHASH_StrHash64Function = __internal__::hash_str;
__LL_VAR_INLINE__ constexpr hash::wStrHash64Function CITYHASH_wStrHash64Function = __internal__::hash_wstr;
__LL_VAR_INLINE__ constexpr hash::RecursiveHash64Function CITYHASH_RecursiveHash64Function = __internal__::hash;
__LL_VAR_INLINE__ constexpr hash::StrTypeidHash64Function CITYHASH_StrTypeidHash64Function = __internal__::empty;
__LL_VAR_INLINE__ constexpr hash::wStrTypeidHash64Function CITYHASH_wStrTypeidHash64Function = __internal__::empty;

__LL_VAR_INLINE__ constexpr hash::Hash64FunctionPack CITYHASH_FUNCTION_PACK = {
	CITYHASH_Hash64Function,
	CITYHASH_wHash64Function,
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
