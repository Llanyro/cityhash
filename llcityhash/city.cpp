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
// This file provides CityHash64() and related functions.
//
// It's probably possible to create even faster hash functions by
// writing a program that systematically explores some of the space of
// possible hash functions, by using SIMD instructions, or by
// compromising on hash quality.

//////////////////////////////////////////////
//	city.cpp								//
//											//
//	Author: Geoff Pike and Jyrki Alakuijala	//
//	Edited: Francisco Julio Ruiz Fernandez	//
//	Edited: llanyro							//
//////////////////////////////////////////////

//#include "config.h"
#include "city.hpp"

#if defined(WINDOWS_SYSTEM)
	#pragma warning(push)
	#pragma warning(disable:4365) // ignore conversion from long to ui32 (signed/unsigned mismatch)
	#include <algorithm>
	#pragma warning(pop)
#else
	#include <algorithm>
#endif // WINDOWS_SYSTEM

#include <cstring>  // for std::memcpy and std::memset

#include <string>

#if defined(WINDOWS_SYSTEM)
	#pragma warning(push)
	#if defined(__LL_SPECTRE_FUNCTIONS__)
		#pragma warning(disable:5045) // Security Spectre mitigation [SECURITY]
	#endif // __LL_UNSECURE_FUNCTIONS__
#endif // WINDOWS_SYSTEM

namespace llcpp {
namespace city {

ui64 UNALIGNED_LOAD64(ll_string_t p) {
	ui64 result;
	std::memcpy(&result, p, sizeof(result));
	return result;
}

ui32 UNALIGNED_LOAD32(ll_string_t p) {
	ui32 result;
	std::memcpy(&result, p, sizeof(result));
	return result;
}

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <sys/types.h>
#include <machine/bswap.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

#if defined(WORDS_BIGENDIAN)
#define ui32_in_expected_order(x) (bswap_32(x))
#define ui64_in_expected_order(x) (bswap_64(x))
#else
#define ui32_in_expected_order(x) (x)
#define ui64_in_expected_order(x) (x)
#endif

#if !defined(LIKELY)
#if defined(HAVE_BUILTIN_EXPECT) && HAVE_BUILTIN_EXPECT
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#else
#define LIKELY(x) (x)
#endif
#endif

ui64 Fetch64(ll_string_t p) noexcept {
	return ui64_in_expected_order(UNALIGNED_LOAD64(p));
}

ui32 Fetch32(ll_string_t p) noexcept {
	return ui32_in_expected_order(UNALIGNED_LOAD32(p));
}

// Some primes between 2^63 and 2^64 for various uses.
constexpr ui64 k0 = llcpp::meta::hash::city::CityHash::k0;
constexpr ui64 k1 = llcpp::meta::hash::city::CityHash::k1;
constexpr ui64 k2 = llcpp::meta::hash::city::CityHash::k2;

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
constexpr ui32 c1 = llcpp::meta::hash::city::CityHash::c1;
constexpr ui32 c2 = llcpp::meta::hash::city::CityHash::c2;

#pragma region Priv
#undef PERMUTE3
#define PERMUTE3(a, b, c) do { std::swap(a, b); std::swap(a, c); } while (0)

// A 32-bit to 32-bit integer hash copied from Murmur3.
ui32 fmix(ui32 h) noexcept {
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

ui32 Rotate32(const ui32 val, const i32 shift) noexcept {
	// Avoid shifting by 32: doing so yields an undefined result.
	return shift == 0 ? val : ((val >> shift) | (val << (32 - shift)));
}

ui32 Mur(ui32 a, ui32 h) noexcept {
	// Helper from Murmur3 for combining two 32-bit values.
	a *= c1;
	a = Rotate32(a, 17);
	a *= c2;
	h ^= a;
	h = Rotate32(h, 19);
	return h * 5 + 0xe6546b64;
}

ui32 Hash32Len13to24(ll_string_t s, const len_t len) noexcept {
	ui32 a = Fetch32(s - 4 + (len >> 1));
	ui32 b = Fetch32(s + 4);
	ui32 c = Fetch32(s + len - 8);
	ui32 d = Fetch32(s + (len >> 1));
	ui32 e = Fetch32(s);
	ui32 f = Fetch32(s + len - 4);
	ui32 h = static_cast<ui32>(len);

	return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

ui32 Hash32Len0to4(ll_string_t s, const len_t len) noexcept {
	ui32 b = 0;
	ui32 c = 9;
	for (len_t i = 0; i < len; ++i) {
		signed char v = static_cast<signed char>(s[i]);
		b = b * c1 + static_cast<ui32>(v);
		c ^= b;
	}
	return fmix(Mur(b, Mur(static_cast<ui32>(len), c)));
}

ui32 Hash32Len5to12(ll_string_t s, const len_t len) noexcept {
	ui32 a = static_cast<ui32>(len), b = a * 5, c = 9, d = b;
	a += Fetch32(s);
	b += Fetch32(s + len - 4);
	c += Fetch32(s + ((len >> 1) & 4));
	return fmix(Mur(c, Mur(b, Mur(a, d))));
}


// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
ui64 Rotate(const ui64 val, const i32 shift) noexcept {
	// Avoid shifting by 64: doing so yields an undefined result.
	return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

ui64 ShiftMix(const ui64 val) noexcept {
	return val ^ (val >> 47);
}

//ui64 HashLen16(const ui64 u, const ui64 v) noexcept {
//    return hash::Hash128(u, v).toui64();
//}

ui64 HashLen16(const ui64 u, const ui64 v, const ui64 mul) noexcept {
	// Murmur-inspired hashing.
	ui64 a = (u ^ v) * mul;
	a ^= (a >> 47);
	ui64 b = (v ^ a) * mul;
	b ^= (b >> 47);
	b *= mul;
	return b;
}

ui64 HashLen0to16(ll_string_t s, const len_t len) noexcept {
	if (len >= 8) {
		ui64 mul = k2 + len * 2;
		ui64 a = Fetch64(s) + k2;
		ui64 b = Fetch64(s + len - 8);
		ui64 c = Rotate(b, 37) * mul + a;
		ui64 d = (Rotate(a, 25) + b) * mul;
		return HashLen16(c, d, mul);
	}
	if (len >= 4) {
		ui64 mul = k2 + len * 2;
		ui64 a = Fetch32(s);
		return HashLen16(len + (a << 3), Fetch32(s + len - 4), mul);
	}
	if (len > 0) {
		ui8 a = static_cast<ui8>(s[0]);
		ui8 b = static_cast<ui8>(s[len >> 1]);
		ui8 c = static_cast<ui8>(s[len - 1]);
		ui32 y = static_cast<ui32>(a) + (static_cast<ui32>(b) << 8);
		ui32 z = static_cast<ui32>(len) + (static_cast<ui32>(c) << 2);
		return ShiftMix(y * k2 ^ z * k0) * k2;
	}
	return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
ui64 HashLen17to32(ll_string_t s, const len_t len) noexcept {
	ui64 mul = k2 + len * 2;
	ui64 a = Fetch64(s) * k1;
	ui64 b = Fetch64(s + 8);
	ui64 c = Fetch64(s + len - 8) * mul;
	ui64 d = Fetch64(s + len - 16) * k2;
	return HashLen16(Rotate(a + b, 43) + Rotate(c, 30) + d,
		a + Rotate(b + k2, 18) + c, mul);
}

// Return an 8-byte hash for 33 to 64 bytes.
ui64 HashLen33to64(ll_string_t s, const len_t len) noexcept {
	ui64 mul = k2 + len * 2;
	ui64 a = Fetch64(s) * k2;
	ui64 b = Fetch64(s + 8);
	ui64 c = Fetch64(s + len - 24);
	ui64 d = Fetch64(s + len - 32);
	ui64 e = Fetch64(s + 16) * k2;
	ui64 f = Fetch64(s + 24) * 9;
	ui64 g = Fetch64(s + len - 8);
	ui64 h = Fetch64(s + len - 16) * mul;
	ui64 u = Rotate(a + g, 43) + (Rotate(b, 30) + c) * 9;
	ui64 v = ((a + g) ^ d) + f + 1;
	ui64 w = bswap_64((u + v) * mul) + h;
	ui64 x = Rotate(e + f, 42) + c;
	ui64 y = (bswap_64((v + w) * mul) + g) * mul;
	ui64 z = e + f + c;
	a = bswap_64((x + z) * mul + y) + b;
	b = ShiftMix((z + a) * mul + d + h) * mul;
	return b + x;
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
hash::Hash128 WeakHashLen32WithSeeds(const ui64 w, const ui64 x, const ui64 y, const ui64 z, ui64 a, ui64 b) noexcept {
	a += w;
	b = Rotate(b + a + z, 21);
	ui64 c = a;
	a += x;
	a += y;
	b += Rotate(a, 44);
	return hash::Hash128(a + z, b + c);
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
hash::Hash128 WeakHashLen32WithSeeds(ll_string_t s, const ui64 a, const ui64 b) noexcept {
	return WeakHashLen32WithSeeds(
		Fetch64(s), Fetch64(s + 8),
		Fetch64(s + 16), Fetch64(s + 24),
		a, b);
}

// A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
// of any length representable in signed long.  Based on City and Murmur.
hash::Hash128 CityMurmur(ll_string_t s, len_t len, const hash::Hash128& seed) noexcept {
	ui64 a = seed.getLow();
	ui64 b = seed.getHigh();
	ui64 c = 0;
	ui64 d = 0;
	if (len <= 16) {
		a = ShiftMix(a * k1) * k1;
		c = b * k1 + HashLen0to16(s, len);
		d = ShiftMix(a + (len >= 8 ? Fetch64(s) : c));
	}
	else {
		c = hash::Hash128(Fetch64(s + len - 8) + k1, a);
		d = hash::Hash128(b + len, c + Fetch64(s + len - 16));
		a += d;
		// len > 16 here, so do...while is safe
		do {
			a ^= ShiftMix(Fetch64(s) * k1) * k1;
			a *= k1;
			b ^= a;
			c ^= ShiftMix(Fetch64(s + 8) * k1) * k1;
			c *= k1;
			d ^= c;
			s += 16;
			len -= 16;
		} while (len > 16);
	}
	a = hash::Hash128(a, c);
	b = hash::Hash128(d, b);
	return hash::Hash128(a ^ b, hash::Hash128(b, a));
}

#pragma endregion
#pragma region Hash32
hash::OptionalHash32 CityHash32(ll_string_t s, const len_t len) noexcept {
	if (!s) return hash::INVALID_HASH32;

	if (len <= 24) {
		return len <= 12 ?
			(len <= 4 ? Hash32Len0to4(s, len) : Hash32Len5to12(s, len)) :
			Hash32Len13to24(s, len);
	}

	// len > 24
	ui32 h = static_cast<ui32>(len), g = c1 * h, f = g;
	ui32 b0 = Rotate32(Fetch32(s + len - 4) * c1, 17) * c2;
	ui32 b1 = Rotate32(Fetch32(s + len - 8) * c1, 17) * c2;
	ui32 b2 = Rotate32(Fetch32(s + len - 16) * c1, 17) * c2;
	ui32 b3 = Rotate32(Fetch32(s + len - 12) * c1, 17) * c2;
	ui32 b4 = Rotate32(Fetch32(s + len - 20) * c1, 17) * c2;
	h ^= b0;
	h = Rotate32(h, 19);
	h = h * 5 + 0xe6546b64;
	h ^= b2;
	h = Rotate32(h, 19);
	h = h * 5 + 0xe6546b64;
	g ^= b1;
	g = Rotate32(g, 19);
	g = g * 5 + 0xe6546b64;
	g ^= b3;
	g = Rotate32(g, 19);
	g = g * 5 + 0xe6546b64;
	f += b4;
	f = Rotate32(f, 19);
	f = f * 5 + 0xe6546b64;
	len_t iters = (len - 1) / 20;
	do {
		ui32 a0 = Rotate32(Fetch32(s) * c1, 17) * c2;
		ui32 a1 = Fetch32(s + 4);
		ui32 a2 = Rotate32(Fetch32(s + 8) * c1, 17) * c2;
		ui32 a3 = Rotate32(Fetch32(s + 12) * c1, 17) * c2;
		ui32 a4 = Fetch32(s + 16);
		h ^= a0;
		h = Rotate32(h, 18);
		h = h * 5 + 0xe6546b64;
		f += a1;
		f = Rotate32(f, 19);
		f = f * c1;
		g += a2;
		g = Rotate32(g, 18);
		g = g * 5 + 0xe6546b64;
		h ^= a3 + a1;
		h = Rotate32(h, 19);
		h = h * 5 + 0xe6546b64;
		g ^= a4;
		g = bswap_32(g) * 5;
		h += a4 * 5;
		h = bswap_32(h);
		f += a0;
		PERMUTE3(f, h, g);
		s += 20;
	} while (--iters != 0);
	g = Rotate32(g, 11) * c1;
	g = Rotate32(g, 17) * c1;
	f = Rotate32(f, 11) * c1;
	f = Rotate32(f, 17) * c1;
	h = Rotate32(h + g, 19);
	h = h * 5 + 0xe6546b64;
	h = Rotate32(h, 17) * c1;
	h = Rotate32(h + f, 19);
	h = h * 5 + 0xe6546b64;
	h = Rotate32(h, 17) * c1;
	return h;
}

#pragma endregion
#pragma region Hash64
hash::OptionalHash64 CityHash64(ll_string_t s, len_t len) noexcept {
	if (!s) return std::nullopt;
	if (len <= 32) {
		if (len <= 16) return HashLen0to16(s, len);
		else return HashLen17to32(s, len);
	}
	else if (len <= 64) return HashLen33to64(s, len);

	// For strings over 64 bytes we hash the end first, and then as we
	// loop we keep 56 bytes of state: v, w, x, y, and z.
	ui64 x = Fetch64(s + len - 40);
	ui64 y = Fetch64(s + len - 16) + Fetch64(s + len - 56);
	ui64 z = hash::Hash128(Fetch64(s + len - 48) + len, Fetch64(s + len - 24));
	hash::Hash128 v = WeakHashLen32WithSeeds(s + len - 64, len, z);
	hash::Hash128 w = WeakHashLen32WithSeeds(s + len - 32, y + k1, x);
	x = x * k1 + Fetch64(s);

	// Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
	len = (len - 1) & ~static_cast<len_t>(63);
	do {
		x = Rotate(x + y + v.getLow() + Fetch64(s + 8), 37) * k1;
		y = Rotate(y + v.getHigh() + Fetch64(s + 48), 42) * k1;
		x ^= w.getHigh();
		y += v.getLow() + Fetch64(s + 40);
		z = Rotate(z + w.getLow(), 33) * k1;
		v = WeakHashLen32WithSeeds(s, v.getHigh() * k1, x + w.getLow());
		w = WeakHashLen32WithSeeds(s + 32, z + w.getHigh(), y + Fetch64(s + 16));
		std::swap(z, x);
		s += 64;
		len -= 64;
	} while (len != 0);
	return hash::Hash128(
		hash::Hash128(v.getLow(), w.getLow()) + ShiftMix(y) * k1 + z,
		hash::Hash128(v.getHigh(), w.getHigh()) + x
	).toHash64();
}
hash::OptionalHash64 CityHash64(ll_wstring_t str, len_t size) noexcept {
	constexpr len_t PARSER_BUFFER_SIZE = 512;
	ll_char_t buffer[PARSER_BUFFER_SIZE]{};
	len_t buffer_len = sizeof(ll_wchar_t) * size;
	if (buffer_len > PARSER_BUFFER_SIZE) return hash::INVALID_HASH64;

	ll_char_t* i = buffer;
	for (ll_wstring_t data_end = str + size; str < data_end; ++str)
		hash::basic_type_hash::conversor<ll_wchar_t>(i, *str);
	return llcpp::city::CityHash64(buffer, buffer_len);
}
hash::OptionalHash64 CityHash64(const std::string& str) noexcept {
	return CityHash64(str.c_str(), str.size());
}
hash::OptionalHash64 CityHash64(const std::wstring& str) noexcept {
	return CityHash64(str.c_str(), str.size());
}
hash::OptionalHash64 CityHash64(const meta::StrPair& str) noexcept {
	return CityHash64(str.begin(), str.len());
}
hash::OptionalHash64 CityHash64(const meta::wStrPair& str) noexcept {
	return CityHash64(str.begin(), str.len());
}
hash::OptionalHash64 CityHash64(const meta::Str& str) noexcept {
	return CityHash64(str.begin(), str.len());
}
hash::OptionalHash64 CityHash64(const meta::wStr& str) noexcept {
	return CityHash64(str.begin(), str.len());
}
hash::OptionalHash64 CityHash64(const hash::Hash64& h) noexcept {
	return hash::basic_type_hash::hashValue<ui64>(h.get(), llcpp::city::CityHash64);
}

hash::OptionalHash64 CityHash64WithSeed(ll_string_t s, const len_t len, const ui64 seed) noexcept {
	return CityHash64WithSeeds(s, len, k2, seed);
}
hash::OptionalHash64 CityHash64WithSeeds(ll_string_t s, const len_t len, const ui64 seed0, const ui64 seed1) noexcept {
	if (!s) return std::nullopt;
	return hash::Hash128((*CityHash64(s, len)).get() - seed0, seed1).toHash64();
}

#pragma endregion
#pragma region Hash128
hash::OptionalHash128 CityHash128(ll_string_t s, len_t len) noexcept {
	if (!s) return std::nullopt;
	return len >= 16 ?
		CityHash128WithSeed(s + 16, len - 16, hash::Hash128(Fetch64(s), Fetch64(s + 8) + k0)) :
		CityHash128WithSeed(s, len, hash::Hash128(k0, k1));
}
hash::OptionalHash128 CityHash128WithSeed(ll_string_t s, len_t len, const hash::Hash128& seed) noexcept {
	if (len < 128)
		return CityMurmur(s, len, seed);

	// We expect len >= 128 to be the common case.  Keep 56 bytes of state:
	// v, w, x, y, and z.
	hash::Hash128 v, w;
	ui64 x = seed.getLow();
	ui64 y = seed.getHigh();
	ui64 z = len * k1;
	v[0] = Rotate(y ^ k1, 49) * k1 + Fetch64(s);
	v[1] = Rotate(v.getLow(), 42) * k1 + Fetch64(s + 8);
	w[0] = Rotate(y + z, 35) * k1 + x;
	w[1] = Rotate(x + Fetch64(s + 88), 53) * k1;

	// This is the same inner loop as CityHash64(), manually unrolled.
	do {
		x = Rotate(x + y + v.getLow() + Fetch64(s + 8), 37) * k1;
		y = Rotate(y + v.getHigh() + Fetch64(s + 48), 42) * k1;
		x ^= w.getHigh();
		y += v.getLow() + Fetch64(s + 40);
		z = Rotate(z + w.getLow(), 33) * k1;
		v = WeakHashLen32WithSeeds(s, v.getHigh() * k1, x + w.getLow());
		w = WeakHashLen32WithSeeds(s + 32, z + w.getHigh(), y + Fetch64(s + 16));
		std::swap(z, x);
		s += 64;
		x = Rotate(x + y + v.getLow() + Fetch64(s + 8), 37) * k1;
		y = Rotate(y + v.getHigh() + Fetch64(s + 48), 42) * k1;
		x ^= w.getHigh();
		y += v.getLow() + Fetch64(s + 40);
		z = Rotate(z + w.getLow(), 33) * k1;
		v = WeakHashLen32WithSeeds(s, v.getHigh() * k1, x + w.getLow());
		w = WeakHashLen32WithSeeds(s + 32, z + w.getHigh(), y + Fetch64(s + 16));
		std::swap(z, x);
		s += 64;
		len -= 128;
	} while (LIKELY(len >= 128));
	x += Rotate(v.getLow() + z, 49) * k0;
	y = y * k0 + Rotate(w.getHigh(), 37);
	z = z * k0 + Rotate(w.getLow(), 27);
	w[0] *= 9;
	v[0] *= k0;
	// If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s.
	for (len_t tail_done = 0; tail_done < len; ) {
		tail_done += 32;
		y = Rotate(x + y, 42) * k0 + v.getHigh();
		w[0] += Fetch64(s + len - tail_done + 16);
		x = x * k0 + w.getLow();
		z += w.getHigh() + Fetch64(s + len - tail_done);
		w[1] += v.getLow();
		v = WeakHashLen32WithSeeds(s + len - tail_done, v.getLow() + z, v.getHigh());
		v[0] *= k0;
	}
	// At this point our 56 bytes of state should contain more than
	// enough information for a strong 128-bit hash.  We use two
	// different 56-byte-to-8-byte hashes to get a 16-byte final result.
	x = hash::Hash128(x, v.getLow());
	y = hash::Hash128(y + z, w.getLow());
	return hash::Hash128(
		hash::Hash128(x + v.getHigh(), w.getHigh()) + y,
		hash::Hash128(x + w.getHigh(), y + v.getHigh()
	));
}

#pragma endregion

#ifdef __SSE4_2__
#include <citycrc.h>
#include <nmmintrin.h>

// Requires len >= 240.
void CityHashCrc256Long(ll_string_t s, len_t len,
	ui32 seed, ui64* result) noexcept {
	ui64 a = Fetch64(s + 56) + k0;
	ui64 b = Fetch64(s + 96) + k0;
	ui64 c = result[0] = HashLen16(b, len);
	ui64 d = result[1] = Fetch64(s + 120) * k0 + len;
	ui64 e = Fetch64(s + 184) + seed;
	ui64 f = 0;
	ui64 g = 0;
	ui64 h = c + d;
	ui64 x = seed;
	ui64 y = 0;
	ui64 z = 0;

	// 240 bytes of input per iter.
	len_t iters = len / 240;
	len -= iters * 240;
	do {
#undef CHUNK
#define CHUNK(r)                            \
PERMUTE3(x, z, y);                          \
b += Fetch64(s);                            \
c += Fetch64(s + 8);                        \
d += Fetch64(s + 16);                       \
e += Fetch64(s + 24);                       \
f += Fetch64(s + 32);                       \
a += b;                                     \
h += f;                                     \
b += c;                                     \
f += d;                                     \
g += e;                                     \
e += z;                                     \
g += x;                                     \
z = _mm_crc32_u64(z, b + g);                \
y = _mm_crc32_u64(y, e + h);                \
x = _mm_crc32_u64(x, f + a);                \
e = Rotate(e, r);                           \
c += e;                                     \
s += 40

		CHUNK(0); PERMUTE3(a, h, c);
		CHUNK(33); PERMUTE3(a, h, f);
		CHUNK(0); PERMUTE3(b, h, f);
		CHUNK(42); PERMUTE3(b, h, d);
		CHUNK(0); PERMUTE3(b, h, e);
		CHUNK(33); PERMUTE3(a, h, e);
	} while (--iters > 0);

	while (len >= 40) {
		CHUNK(29);
		e ^= Rotate(a, 20);
		h += Rotate(b, 30);
		g ^= Rotate(c, 40);
		f += Rotate(d, 34);
		PERMUTE3(c, h, g);
		len -= 40;
	}
	if (len > 0) {
		s = s + len - 40;
		CHUNK(33);
		e ^= Rotate(a, 43);
		h += Rotate(b, 42);
		g ^= Rotate(c, 41);
		f += Rotate(d, 40);
	}
	result[0] ^= h;
	result[1] ^= g;
	g += h;
	a = HashLen16(a, g + z);
	x += y << 32;
	b += x;
	c = HashLen16(c, z) + h;
	d = HashLen16(d, e + result[0]);
	g += e;
	h += HashLen16(x, f);
	e = HashLen16(a, d) + g;
	z = HashLen16(b, c) + a;
	y = HashLen16(g, h) + c;
	result[0] = e + z + y + x;
	a = ShiftMix((a + y) * k0) * k0 + b;
	result[1] += a + result[0];
	a = ShiftMix(a * k0) * k0 + c;
	result[2] = a + result[1];
	a = ShiftMix((a + e) * k0) * k0;
	result[3] = a + result[2];
}

// Requires len < 240.
void CityHashCrc256Short(ll_string_t s, len_t len, ui64* result) noexcept {
	char buf[240];
	std::memcpy(buf, s, len);
	std::memset(buf + len, 0, 240 - len);
	CityHashCrc256Long(buf, 240, ~static_cast<ui32>(len), result);
}

void CityHashCrc256(ll_string_t s, len_t len, ui64* result) noexcept {
	if (LIKELY(len >= 240)) {
		CityHashCrc256Long(s, len, 0, result);
	}
	else {
		CityHashCrc256Short(s, len, result);
	}
}

hash128 CityHashCrc128WithSeed(ll_string_t s, len_t len, hash128 seed) noexcept {
	if (len <= 900) {
		return CityHash128WithSeed(s, len, seed);
	}
	else {
		ui64 result[4];
		CityHashCrc256(s, len, result);
		ui64 u = Uint128High64(seed) + result[0];
		ui64 v = Uint128Low64(seed) + result[1];
		return hash128(HashLen16(u, v + result[2]),
			HashLen16(Rotate(v, 32), u * k0 + result[3]));
	}
}

hash128 CityHashCrc128(ll_string_t s, len_t len) noexcept {
	if (len <= 900) {
		return CityHash128(s, len);
	}
	else {
		ui64 result[4];
		CityHashCrc256(s, len, result);
		return hash128(result[2], result[3]);
	}
}

#endif

} // namespace city
} // namespace llcpp

#if defined(WINDOWS_SYSTEM)
	#pragma warning(pop)
#endif // WINDOWS_SYSTEM
