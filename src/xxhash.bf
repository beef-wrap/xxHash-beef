/*
 * xxHash - Extremely Fast Hash algorithm
 * Header File
 * Copyright (C) 2012-2023 Yann Collet
 *
 * BSD 2-Clause License (https://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other materials provided with the
 *      distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at:
 *   - xxHash homepage: https://www.xxhash.com
 *   - xxHash source repository: https://github.com/Cyan4973/xxHash
 */

/*!
 * @mainpage xxHash
 *
 * xxHash is an extremely fast non-cryptographic hash algorithm, working at RAM speed
 * limits.
 *
 * It is proposed in four flavors, in three families:
 * 1. @ref XXH32_family
 *   - Classic 32-bit hash function. Simple, compact, and runs on almost all
 *     32-bit and 64-bit systems.
 * 2. @ref XXH64_family
 *   - Classic 64-bit adaptation of XXH32. Just as simple, and runs well on most
 *     64-bit systems (but _not_ 32-bit systems).
 * 3. @ref XXH3_family
 *   - Modern 64-bit and 128-bit hash function family which features improved
 *     strength and performance across the board, especially on smaller data.
 *     It benefits greatly from SIMD and 64-bit without requiring it.
 *
 * Benchmarks
 * ---
 * The reference system uses an Intel i7-9700K CPU, and runs Ubuntu x64 20.04.
 * The open source benchmark program is compiled with clang v10.0 using -O3 flag.
 *
 * | Hash Name            | ISA ext | Width | Large Data Speed | Small Data Velocity |
 * | -------------------- | ------- | ----: | ---------------: | ------------------: |
 * | XXH3_64bits()        | @b AVX2 |    64 |        59.4 GB/s |               133.1 |
 * | MeowHash             | AES-NI  |   128 |        58.2 GB/s |                52.5 |
 * | XXH3_128bits()       | @b AVX2 |   128 |        57.9 GB/s |               118.1 |
 * | CLHash               | PCLMUL  |    64 |        37.1 GB/s |                58.1 |
 * | XXH3_64bits()        | @b SSE2 |    64 |        31.5 GB/s |               133.1 |
 * | XXH3_128bits()       | @b SSE2 |   128 |        29.6 GB/s |               118.1 |
 * | RAM sequential read  |         |   N/A |        28.0 GB/s |                 N/A |
 * | ahash                | AES-NI  |    64 |        22.5 GB/s |               107.2 |
 * | City64               |         |    64 |        22.0 GB/s |                76.6 |
 * | T1ha2                |         |    64 |        22.0 GB/s |                99.0 |
 * | City128              |         |   128 |        21.7 GB/s |                57.7 |
 * | FarmHash             | AES-NI  |    64 |        21.3 GB/s |                71.9 |
 * | XXH64()              |         |    64 |        19.4 GB/s |                71.0 |
 * | SpookyHash           |         |    64 |        19.3 GB/s |                53.2 |
 * | Mum                  |         |    64 |        18.0 GB/s |                67.0 |
 * | CRC32C               | SSE4.2  |    32 |        13.0 GB/s |                57.9 |
 * | XXH32()              |         |    32 |         9.7 GB/s |                71.9 |
 * | City32               |         |    32 |         9.1 GB/s |                66.0 |
 * | Blake3*              | @b AVX2 |   256 |         4.4 GB/s |                 8.1 |
 * | Murmur3              |         |    32 |         3.9 GB/s |                56.1 |
 * | SipHash*             |         |    64 |         3.0 GB/s |                43.2 |
 * | Blake3*              | @b SSE2 |   256 |         2.4 GB/s |                 8.1 |
 * | HighwayHash          |         |    64 |         1.4 GB/s |                 6.0 |
 * | FNV64                |         |    64 |         1.2 GB/s |                62.7 |
 * | Blake2*              |         |   256 |         1.1 GB/s |                 5.1 |
 * | SHA1*                |         |   160 |         0.8 GB/s |                 5.6 |
 * | MD5*                 |         |   128 |         0.6 GB/s |                 7.8 |
 * @note
 *   - Hashes which require a specific ISA extension are noted. SSE2 is also noted,
 *     even though it is mandatory on x64.
 *   - Hashes with an asterisk are cryptographic. Note that MD5 is non-cryptographic
 *     by modern standards.
 *   - Small data velocity is a rough average of algorithm's efficiency for small
 *     data. For more accurate information, see the wiki.
 *   - More benchmarks and strength tests are found on the wiki:
 *         https://github.com/Cyan4973/xxHash/wiki
 *
 * Usage
 * ------
 * All xxHash variants use a similar API. Changing the algorithm is a trivial
 * substitution.
 *
 * @pre
 *    For functions which take an input and length parameter, the following
 *    requirements are assumed:
 *    - The range from [`input`, `input + length`) is valid, readable memory.
 *      - The only exception is if the `length` is `0`, `input` may be `NULL`.
 *    - For C++, the objects must have the *TriviallyCopyable* property, as the
 *      functions access bytes directly as if it was an array of `c_uchar`.
 *
 * @anchor single_shot_example
 * **Single Shot**
 *
 * These functions are stateless functions which hash a contiguous block of memory,
 * immediately returning the result. They are the easiest and usually the fastest
 * option.
 *
 * XXH32(), XXH64(), XXH3_64bits(), XXH3_128bits()
 *
 * @code{.c}
 *   #include <string.h>
 *   #include "xxhash.h"
 *
 *   // Example for a function which hashes a null terminated string with XXH32().
 *   XXH32_hash_t hash_string(char* string, XXH32_hash_t seed)
 *   {
 *       // NULL pointers are only valid if the length is zero
 *       size_t length = (string == NULL) ? 0 : strlen(string);
 *       return XXH32(string, length, seed);
 *   }
 * @endcode
 *
 *
 * @anchor streaming_example
 * **Streaming**
 *
 * These groups of functions allow incremental hashing of unknown size, even
 * more than what would fit in a size_t.
 *
 * XXH32_reset(), XXH64_reset(), XXH3_64bits_reset(), XXH3_128bits_reset()
 *
 * @code{.c}
 *   #include <stdio.h>
 *   #include <assert.h>
 *   #include "xxhash.h"
 *   // Example for a function which hashes a FILE incrementally with XXH3_64bits().
 *   XXH64_hash_t hashFile(FILE* f)
 *   {
 *       // Allocate a state struct. Do not just use malloc() or new.
 *       XXH3_state_t* state = XXH3_createState();
 *       assert(state != NULL && "Out of memory!");
 *       // Reset the state to start a new hashing session.
 *       XXH3_64bits_reset(state);
 *       char buffer[4096];
 *       size_t count;
 *       // Read the file in chunks
 *       while ((count = fread(buffer, 1, sizeof(buffer), f)) != 0) {
 *           // Run update() as many times as necessary to process the data
 *           XXH3_64bits_update(state, buffer, count);
 *       }
 *       // Retrieve the finalized hash. This will not change the state.
 *       XXH64_hash_t result = XXH3_64bits_digest(state);
 *       // Free the state. Do not use free().
 *       XXH3_freeState(state);
 *       return result;
 *   }
 * @endcode
 *
 * Streaming functions generate the xxHash value from an incremental input.
 * This method is slower than single-call functions, due to state management.
 * For small inputs, prefer `XXH32()` and `XXH64()`, which are better optimized.
 *
 * An XXH state must first be allocated using `XXH*_createState()`.
 *
 * Start a new hash by initializing the state with a seed using `XXH*_reset()`.
 *
 * Then, feed the hash state by calling `XXH*_update()` as many times as necessary.
 *
 * The function returns an error code, with 0 meaning OK, and any other value
 * meaning there is an error.
 *
 * Finally, a hash value can be produced anytime, by using `XXH*_digest()`.
 * This function returns the nn-bits hash as an int or long long.
 *
 * It's still possible to continue inserting input into the hash state after a
 * digest, and generate new hash values later on by invoking `XXH*_digest()`.
 *
 * When done, release the state using `XXH*_freeState()`.
 *
 *
 * @anchor canonical_representation_example
 * **Canonical Representation**
 *
 * The default return values from XXH functions are unsigned 32, 64 and 128 bit
 * integers.
 * This the simplest and fastest format for further post-processing.
 *
 * However, this leaves open the question of what is the order on the byte level,
 * since little and big endian conventions will store the same number differently.
 *
 * The canonical representation settles this issue by mandating big-endian
 * convention, the same convention as human-readable numbers (large digits first).
 *
 * When writing hash values to storage, sending them over a network, or printing
 * them, it's highly recommended to use the canonical representation to ensure
 * portability across a wider range of systems, present and future.
 *
 * The following functions allow transformation of hash values to and from
 * canonical format.
 *
 * XXH32_canonicalFromHash(), XXH32_hashFromCanonical(),
 * XXH64_canonicalFromHash(), XXH64_hashFromCanonical(),
 * XXH128_canonicalFromHash(), XXH128_hashFromCanonical(),
 *
 * @code{.c}
 *   #include <stdio.h>
 *   #include "xxhash.h"
 *
 *   // Example for a function which prints XXH32_hash_t in human readable format
 *   void printXxh32(XXH32_hash_t hash)
 *   {
 *       XXH32_canonical_t cano;
 *       XXH32_canonicalFromHash(&cano, hash);
 *       size_t i;
 *       for(i = 0; i < sizeof(cano.digest); ++i) {
 *           printf("%02x", cano.digest[i]);
 *       }
 *       printf("\n");
 *   }
 *
 *   // Example for a function which converts XXH32_canonical_t to XXH32_hash_t
 *   XXH32_hash_t convertCanonicalToXxh32(XXH32_canonical_t cano)
 *   {
 *       XXH32_hash_t hash = XXH32_hashFromCanonical(&cano);
 *       return hash;
 *   }
 * @endcode
 *
 *
 * @file xxhash.h
 * xxHash prototypes and implementation
 */

using System;
using System.Interop;

namespace xxHash;

public static class xxHash
{
	typealias char = c_char;
	typealias size_t = uint;
	typealias uint32_t = uint32;
	typealias uint64_t = uint64;

	// #ifdef XXH_NAMESPACE
	// #  define XXH_CAT(A,B) A##B
	// #  define XXH_NAME2(A,B) XXH_CAT(A,B)
	// #  define XXH_versionNumber XXH_NAME2(XXH_NAMESPACE, XXH_versionNumber)
	// /* XXH32 */
	// #  define XXH32 XXH_NAME2(XXH_NAMESPACE, XXH32)
	// #  define XXH32_createState XXH_NAME2(XXH_NAMESPACE, XXH32_createState)
	// #  define XXH32_freeState XXH_NAME2(XXH_NAMESPACE, XXH32_freeState)
	// #  define XXH32_reset XXH_NAME2(XXH_NAMESPACE, XXH32_reset)
	// #  define XXH32_update XXH_NAME2(XXH_NAMESPACE, XXH32_update)
	// #  define XXH32_digest XXH_NAME2(XXH_NAMESPACE, XXH32_digest)
	// #  define XXH32_copyState XXH_NAME2(XXH_NAMESPACE, XXH32_copyState)
	// #  define XXH32_canonicalFromHash XXH_NAME2(XXH_NAMESPACE, XXH32_canonicalFromHash)
	// #  define XXH32_hashFromCanonical XXH_NAME2(XXH_NAMESPACE, XXH32_hashFromCanonical)
	// /* XXH64 */
	// #  define XXH64 XXH_NAME2(XXH_NAMESPACE, XXH64)
	// #  define XXH64_createState XXH_NAME2(XXH_NAMESPACE, XXH64_createState)
	// #  define XXH64_freeState XXH_NAME2(XXH_NAMESPACE, XXH64_freeState)
	// #  define XXH64_reset XXH_NAME2(XXH_NAMESPACE, XXH64_reset)
	// #  define XXH64_update XXH_NAME2(XXH_NAMESPACE, XXH64_update)
	// #  define XXH64_digest XXH_NAME2(XXH_NAMESPACE, XXH64_digest)
	// #  define XXH64_copyState XXH_NAME2(XXH_NAMESPACE, XXH64_copyState)
	// #  define XXH64_canonicalFromHash XXH_NAME2(XXH_NAMESPACE, XXH64_canonicalFromHash)
	// #  define XXH64_hashFromCanonical XXH_NAME2(XXH_NAMESPACE, XXH64_hashFromCanonical)
	// /* XXH3_64bits */
	// #  define XXH3_64bits XXH_NAME2(XXH_NAMESPACE, XXH3_64bits)
	// #  define XXH3_64bits_withSecret XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_withSecret)
	// #  define XXH3_64bits_withSeed XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_withSeed)
	// #  define XXH3_64bits_withSecretandSeed XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_withSecretandSeed)
	// #  define XXH3_createState XXH_NAME2(XXH_NAMESPACE, XXH3_createState)
	// #  define XXH3_freeState XXH_NAME2(XXH_NAMESPACE, XXH3_freeState)
	// #  define XXH3_copyState XXH_NAME2(XXH_NAMESPACE, XXH3_copyState)
	// #  define XXH3_64bits_reset XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_reset)
	// #  define XXH3_64bits_reset_withSeed XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_reset_withSeed)
	// #  define XXH3_64bits_reset_withSecret XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_reset_withSecret)
	// #  define XXH3_64bits_reset_withSecretandSeed XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_reset_withSecretandSeed)
	// #  define XXH3_64bits_update XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_update)
	// #  define XXH3_64bits_digest XXH_NAME2(XXH_NAMESPACE, XXH3_64bits_digest)
	// #  define XXH3_generateSecret XXH_NAME2(XXH_NAMESPACE, XXH3_generateSecret)
	// #  define XXH3_generateSecret_fromSeed XXH_NAME2(XXH_NAMESPACE, XXH3_generateSecret_fromSeed)
	// /* XXH3_128bits */
	// #  define XXH128 XXH_NAME2(XXH_NAMESPACE, XXH128)
	// #  define XXH3_128bits XXH_NAME2(XXH_NAMESPACE, XXH3_128bits)
	// #  define XXH3_128bits_withSeed XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_withSeed)
	// #  define XXH3_128bits_withSecret XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_withSecret)
	// #  define XXH3_128bits_withSecretandSeed XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_withSecretandSeed)
	// #  define XXH3_128bits_reset XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_reset)
	// #  define XXH3_128bits_reset_withSeed XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_reset_withSeed)
	// #  define XXH3_128bits_reset_withSecret XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_reset_withSecret)
	// #  define XXH3_128bits_reset_withSecretandSeed XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_reset_withSecretandSeed)
	// #  define XXH3_128bits_update XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_update)
	// #  define XXH3_128bits_digest XXH_NAME2(XXH_NAMESPACE, XXH3_128bits_digest)
	// #  define XXH128_isEqual XXH_NAME2(XXH_NAMESPACE, XXH128_isEqual)
	// #  define XXH128_cmp     XXH_NAME2(XXH_NAMESPACE, XXH128_cmp)
	// #  define XXH128_canonicalFromHash XXH_NAME2(XXH_NAMESPACE, XXH128_canonicalFromHash)
	// #  define XXH128_hashFromCanonical XXH_NAME2(XXH_NAMESPACE, XXH128_hashFromCanonical)
	// #endif

	/* *************************************
	*  Version
	***************************************/
	const c_int XXH_VERSION_MAJOR    = 0;
	const c_int XXH_VERSION_MINOR    = 8;
	const c_int XXH_VERSION_RELEASE  = 3;
	/*! @brief Version number, encoded as two digits each */
	// const c_int XXH_VERSION_NUMBER  (XXH_VERSION_MAJOR *100*100 + XXH_VERSION_MINOR *100 + XXH_VERSION_RELEASE);

	/*!
	* @brief Obtains the xxHash version.
	*
	* This is mostly useful when xxHash is compiled as a shared library,
	* since the returned value comes from the library, as opposed to header file.
	*
	* @return @ref XXH_VERSION_NUMBER of the invoked library.
	*/
	[CLink] public static extern c_uint XXH_versionNumber();

	/* ****************************
	*  Common basic types
	******************************/

	/*!
	* @brief Exit code for the streaming API.
	*/
	public enum XXH_errorcode
	{
		XXH_OK = 0, /*!< OK */
		XXH_ERROR /*!< Error */
	}

	/*-**********************************************************************
	*  32-bit hash
	************************************************************************/
	/*!
	* @brief An unsigned 32-bit integer.
	*
	* Not necessarily defined to `uint32_t` but functionally equivalent.
	*/

	typealias XXH32_hash_t = uint32_t;

	/*!
	* @}
	*
	* @defgroup XXH32_family XXH32 family
	* @ingroup public
	* Contains functions used in the classic 32-bit xxHash algorithm.
	*
	* @note
	*   XXH32 is useful for older platforms, with no or poor 64-bit performance.
	*   Note that the @ref XXH3_family provides competitive speed for both 32-bit
	*   and 64-bit systems, and offers true 64/128 bit hash results.
	*
	* @see @ref XXH64_family, @ref XXH3_family : Other xxHash families
	* @see @ref XXH32_impl for implementation details
	* @{
	*/

	/*!
	* @brief Calculates the 32-bit hash of @p input using xxHash32.
	*
	* @param input The block of data to be hashed, at least @p length bytes in size.
	* @param length The length of @p input, in bytes.
	* @param seed The 32-bit seed to alter the hash's output predictably.
	*
	* @pre
	*   The memory between @p input and @p input + @p length must be valid,
	*   readable, contiguous memory. However, if @p length is `0`, @p input may be
	*   `NULL`. In C++, this also must be *TriviallyCopyable*.
	*
	* @return The calculated 32-bit xxHash32 value.
	*
	* @see @ref single_shot_example "Single Shot Example" for an example.
	*/
	[CLink] public static extern XXH32_hash_t XXH32(void* input, size_t length, XXH32_hash_t seed);

#if !XXH_NO_STREAM
	/*!
	* @typedef struct XXH32_state_s XXH32_state_t
	* @brief The opaque state struct for the XXH32 streaming API.
	*
	* @see XXH32_state_s for details.
	* @see @ref streaming_example "Streaming Example"
	*/
	public struct XXH32_state_t;

	/*!
	* @brief Allocates an @ref XXH32_state_t.
	*
	* @return An allocated pointer of @ref XXH32_state_t on success.
	* @return `NULL` on failure.
	*
	* @note Must be freed with XXH32_freeState().
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH32_state_t* XXH32_createState();
	/*!
	* @brief Frees an @ref XXH32_state_t.
	*
	* @param statePtr A pointer to an @ref XXH32_state_t allocated with @ref XXH32_createState().
	*
	* @return @ref XXH_OK.
	*
	* @note @p statePtr must be allocated with XXH32_createState().
	*
	* @see @ref streaming_example "Streaming Example"
	*
	*/
	[CLink] public static extern XXH_errorcode  XXH32_freeState(XXH32_state_t* statePtr);
	/*!
	* @brief Copies one @ref XXH32_state_t to another.
	*
	* @param dst_state The state to copy to.
	* @param src_state The state to copy from.
	* @pre
	*   @p dst_state and @p src_state must not be `NULL` and must not overlap.
	*/
	[CLink] public static extern void XXH32_copyState(XXH32_state_t* dst_state, XXH32_state_t* src_state);

	/*!
	* @brief Resets an @ref XXH32_state_t to begin a new hash.
	*
	* @param statePtr The state struct to reset.
	* @param seed The 32-bit seed to alter the hash result predictably.
	*
	* @pre
	*   @p statePtr must not be `NULL`.
	*
	* @return @ref XXH_OK on success.
	* @return @ref XXH_ERROR on failure.
	*
	* @note This function resets and seeds a state. Call it before @ref XXH32_update().
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH_errorcode XXH32_reset(XXH32_state_t* statePtr, XXH32_hash_t seed);

	/*!
	* @brief Consumes a block of @p input to an @ref XXH32_state_t.
	*
	* @param statePtr The state struct to update.
	* @param input The block of data to be hashed, at least @p length bytes in size.
	* @param length The length of @p input, in bytes.
	*
	* @pre
	*   @p statePtr must not be `NULL`.
	* @pre
	*   The memory between @p input and @p input + @p length must be valid,
	*   readable, contiguous memory. However, if @p length is `0`, @p input may be
	*   `NULL`. In C++, this also must be *TriviallyCopyable*.
	*
	* @return @ref XXH_OK on success.
	* @return @ref XXH_ERROR on failure.
	*
	* @note Call this to incrementally consume blocks of data.
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH_errorcode XXH32_update(XXH32_state_t* statePtr, void* input, size_t length);

	/*!
	* @brief Returns the calculated hash value from an @ref XXH32_state_t.
	*
	* @param statePtr The state struct to calculate the hash from.
	*
	* @pre
	*  @p statePtr must not be `NULL`.
	*
	* @return The calculated 32-bit xxHash32 value from that state.
	*
	* @note
	*   Calling XXH32_digest() will not affect @p statePtr, so you can update,
	*   digest, and update again.
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH32_hash_t XXH32_digest(XXH32_state_t* statePtr);
#endif /* !XXH_NO_STREAM */ 

	/*******   Canonical representation   *******/

	/*!
	* @brief Canonical (big endian) representation of @ref XXH32_hash_t.
	*/
	[CRepr]
	public struct XXH32_canonical_t
	{
		c_uchar[4] digest; /*!< Hash bytes, big endian */
	}

	/*!
	* @brief Converts an @ref XXH32_hash_t to a big endian @ref XXH32_canonical_t.
	*
	* @param dst  The @ref XXH32_canonical_t pointer to be stored to.
	* @param hash The @ref XXH32_hash_t to be converted.
	*
	* @pre
	*   @p dst must not be `NULL`.
	*
	* @see @ref canonical_representation_example "Canonical Representation Example"
	*/
	[CLink] public static extern void XXH32_canonicalFromHash(XXH32_canonical_t* dst, XXH32_hash_t hash);

	/*!
	* @brief Converts an @ref XXH32_canonical_t to a native @ref XXH32_hash_t.
	*
	* @param src The @ref XXH32_canonical_t to convert.
	*
	* @pre
	*   @p src must not be `NULL`.
	*
	* @return The converted hash.
	*
	* @see @ref canonical_representation_example "Canonical Representation Example"
	*/
	[CLink] public static extern XXH32_hash_t XXH32_hashFromCanonical(XXH32_canonical_t* src);

	// /*! @cond Doxygen ignores this part */
	// #ifdef __has_attribute
	// # define XXH_HAS_ATTRIBUTE(x) __has_attribute(x)
	// #else
	// # define XXH_HAS_ATTRIBUTE(x) 0
	// #endif
	// /*! @endcond */

	/*! @cond Doxygen ignores this part */
	/*
	* C23 __STDC_VERSION__ number hasn't been specified yet. For now
	* leave as `201711L` (C17 + 1).
	* TODO: Update to correct value when its been specified.
	*/
	// #define XXH_C23_VN 201711L
	/*! @endcond */

#if !XXH_NO_LONG_LONG
	/*-**********************************************************************
	*  64-bit hash
	************************************************************************/
	/*!
	* @brief An unsigned 64-bit integer.
	*
	* Not necessarily defined to `uint64_t` but functionally equivalent.
	*/
	typealias  XXH64_hash_t = uint64_t;

	/*!
	* @}
	*
	* @defgroup XXH64_family XXH64 family
	* @ingroup public
	* @{
	* Contains functions used in the classic 64-bit xxHash algorithm.
	*
	* @note
	*   XXH3 provides competitive speed for both 32-bit and 64-bit systems,
	*   and offers true 64/128 bit hash results.
	*   It provides better speed for systems with vector processing capabilities.
	*/

	/*!
	* @brief Calculates the 64-bit hash of @p input using xxHash64.
	*
	* @param input The block of data to be hashed, at least @p length bytes in size.
	* @param length The length of @p input, in bytes.
	* @param seed The 64-bit seed to alter the hash's output predictably.
	*
	* @pre
	*   The memory between @p input and @p input + @p length must be valid,
	*   readable, contiguous memory. However, if @p length is `0`, @p input may be
	*   `NULL`. In C++, this also must be *TriviallyCopyable*.
	*
	* @return The calculated 64-bit xxHash64 value.
	*
	* @see @ref single_shot_example "Single Shot Example" for an example.
	*/
	[CLink] public static extern XXH64_hash_t XXH64(void* input, size_t length, XXH64_hash_t seed);

/*******   Streaming   *******/
#if !XXH_NO_STREAM
	/*!
	* @brief The opaque state struct for the XXH64 streaming API.
	*
	* @see XXH64_state_s for details.
	* @see @ref streaming_example "Streaming Example"
	*/
	public struct  XXH64_state_t; /* incomplete type */

	/*!
	* @brief Allocates an @ref XXH64_state_t.
	*
	* @return An allocated pointer of @ref XXH64_state_t on success.
	* @return `NULL` on failure.
	*
	* @note Must be freed with XXH64_freeState().
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH64_state_t* XXH64_createState();

	/*!
	* @brief Frees an @ref XXH64_state_t.
	*
	* @param statePtr A pointer to an @ref XXH64_state_t allocated with @ref XXH64_createState().
	*
	* @return @ref XXH_OK.
	*
	* @note @p statePtr must be allocated with XXH64_createState().
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH_errorcode  XXH64_freeState(XXH64_state_t* statePtr);

	/*!
	* @brief Copies one @ref XXH64_state_t to another.
	*
	* @param dst_state The state to copy to.
	* @param src_state The state to copy from.
	* @pre
	*   @p dst_state and @p src_state must not be `NULL` and must not overlap.
	*/
	[CLink] public static extern void XXH64_copyState(XXH64_state_t* dst_state, XXH64_state_t* src_state);

	/*!
	* @brief Resets an @ref XXH64_state_t to begin a new hash.
	*
	* @param statePtr The state struct to reset.
	* @param seed The 64-bit seed to alter the hash result predictably.
	*
	* @pre
	*   @p statePtr must not be `NULL`.
	*
	* @return @ref XXH_OK on success.
	* @return @ref XXH_ERROR on failure.
	*
	* @note This function resets and seeds a state. Call it before @ref XXH64_update().
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH_errorcode XXH64_reset  (XXH64_state_t* statePtr, XXH64_hash_t seed);

	/*!
	* @brief Consumes a block of @p input to an @ref XXH64_state_t.
	*
	* @param statePtr The state struct to update.
	* @param input The block of data to be hashed, at least @p length bytes in size.
	* @param length The length of @p input, in bytes.
	*
	* @pre
	*   @p statePtr must not be `NULL`.
	* @pre
	*   The memory between @p input and @p input + @p length must be valid,
	*   readable, contiguous memory. However, if @p length is `0`, @p input may be
	*   `NULL`. In C++, this also must be *TriviallyCopyable*.
	*
	* @return @ref XXH_OK on success.
	* @return @ref XXH_ERROR on failure.
	*
	* @note Call this to incrementally consume blocks of data.
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH_errorcode XXH64_update(XXH64_state_t* statePtr, void* input, size_t length);

	/*!
	* @brief Returns the calculated hash value from an @ref XXH64_state_t.
	*
	* @param statePtr The state struct to calculate the hash from.
	*
	* @pre
	*  @p statePtr must not be `NULL`.
	*
	* @return The calculated 64-bit xxHash64 value from that state.
	*
	* @note
	*   Calling XXH64_digest() will not affect @p statePtr, so you can update,
	*   digest, and update again.
	*
	* @see @ref streaming_example "Streaming Example"
	*/
	[CLink] public static extern XXH64_hash_t XXH64_digest(XXH64_state_t* statePtr);
#endif /* !XXH_NO_STREAM */ 

    /*******   Canonical representation   *******/

    /*!
    * @brief Canonical (big endian) representation of @ref XXH64_hash_t.
    */
	[CRepr]
	public struct XXH64_canonical_t
	{
		c_uchar[sizeof(XXH64_hash_t)] digest;
	}

	/*!
	* @brief Converts an @ref XXH64_hash_t to a big endian @ref XXH64_canonical_t.
	*
	* @param dst The @ref XXH64_canonical_t pointer to be stored to.
	* @param hash The @ref XXH64_hash_t to be converted.
	*
	* @pre
	*   @p dst must not be `NULL`.
	*
	* @see @ref canonical_representation_example "Canonical Representation Example"
	*/
	[CLink] public static extern void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash);

	/*!
	* @brief Converts an @ref XXH64_canonical_t to a native @ref XXH64_hash_t.
	*
	* @param src The @ref XXH64_canonical_t to convert.
	*
	* @pre
	*   @p src must not be `NULL`.
	*
	* @return The converted hash.
	*
	* @see @ref canonical_representation_example "Canonical Representation Example"
	*/
	[CLink] public static extern XXH64_hash_t XXH64_hashFromCanonical(XXH64_canonical_t* src);

#if !XXH_NO_XXH3
	/*!
	* @}
	* ************************************************************************
	* @defgroup XXH3_family XXH3 family
	* @ingroup public
	* @{
	*
	* XXH3 is a more recent hash algorithm featuring:
	*  - Improved speed for both small and large inputs
	*  - True 64-bit and 128-bit outputs
	*  - SIMD acceleration
	*  - Improved 32-bit viability
	*
	* Speed analysis methodology is explained here:
	*
	*    https://fastcompression.blogspot.com/2019/03/presenting-xxh3.html
	*
	* Compared to XXH64, expect XXH3 to run approximately
	* ~2x faster on large inputs and >3x faster on small ones,
	* exact differences vary depending on platform.
	*
	* XXH3's speed benefits greatly from SIMD and 64-bit arithmetic,
	* but does not require it.
	* Most 32-bit and 64-bit targets that can run XXH32 smoothly can run XXH3
	* at competitive speeds, even without vector support. Further details are
	* explained in the implementation.
	*
	* XXH3 has a fast scalar implementation, but it also includes accelerated SIMD
	* implementations for many common platforms:
	*   - AVX512
	*   - AVX2
	*   - SSE2
	*   - ARM NEON
	*   - WebAssembly SIMD128
	*   - POWER8 VSX
	*   - s390x ZVector
	* This can be controlled via the @ref XXH_VECTOR macro, but it automatically
	* selects the best version according to predefined macros. For the x86 family, an
	* automatic runtime dispatcher is included separately in @ref xxh_x86dispatch.c.
	*
	* XXH3 implementation is portable:
	* it has a generic C90 formulation that can be compiled on any platform,
	* all implementations generate exactly the same hash value on all platforms.
	* Starting from v0.8.0, it's also labelled "stable", meaning that
	* any future version will also generate the same hash value.
	*
	* XXH3 offers 2 variants, _64bits and _128bits.
	*
	* When only 64 bits are needed, prefer invoking the _64bits variant, as it
	* reduces the amount of mixing, resulting in faster speed on small inputs.
	* It's also generally simpler to manipulate a scalar return type than a struct.
	*
	* The API supports one-shot hashing, streaming mode, and custom secrets.
	*/

    /*!
    * @ingroup tuning
    * @brief Possible values for @ref XXH_VECTOR.
    *
    * Unless set explicitly, determined automatically.
    */
    const c_int XXH_SCALAR = 0; /*!< Portable scalar version */
    const c_int XXH_SSE2   = 1; /*!< SSE2 for Pentium 4, Opteron, all x86_64. */
    const c_int XXH_AVX2   = 2; /*!< AVX2 for Haswell and Bulldozer */
    const c_int XXH_AVX512 = 3; /*!< AVX512 for Skylake and Icelake */
    const c_int XXH_NEON   = 4; /*!< NEON for most ARMv7-A, all AArch64, and WASM SIMD128 */
    const c_int XXH_VSX    = 5; /*!< VSX and ZVector for POWER8/z13 (64-bit) */
    const c_int XXH_SVE    = 6; /*!< SVE for some ARMv8-A and ARMv9-A */
    const c_int XXH_LSX    = 7; /*!< LSX (128-bit SIMD) for LoongArch64 */
    const c_int XXH_LASX   = 8; /*!< LASX (256-bit SIMD) for LoongArch64 */

    /*-**********************************************************************
    *  XXH3 64-bit variant
    ************************************************************************/

    /*!
    * @brief Calculates 64-bit unseeded variant of XXH3 hash of @p input.
    *
    * @param input  The block of data to be hashed, at least @p length bytes in size.
    * @param length The length of @p input, in bytes.
    *
    * @pre
    *   The memory between @p input and @p input + @p length must be valid,
    *   readable, contiguous memory. However, if @p length is `0`, @p input may be
    *   `NULL`. In C++, this also must be *TriviallyCopyable*.
    *
    * @return The calculated 64-bit XXH3 hash value.
    *
    * @note
    *   This is equivalent to @ref XXH3_64bits_withSeed() with a seed of `0`, however
    *   it may have slightly better performance due to constant propagation of the
    *   defaults.
    *
    * @see
    *    XXH3_64bits_withSeed(), XXH3_64bits_withSecret(): other seeding variants
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
	[CLink] public static extern XXH64_hash_t XXH3_64bits(void* input, size_t length);

	/*!
	* @brief Calculates 64-bit seeded variant of XXH3 hash of @p input.
	*
	* @param input  The block of data to be hashed, at least @p length bytes in size.
	* @param length The length of @p input, in bytes.
	* @param seed   The 64-bit seed to alter the hash result predictably.
	*
	* @pre
	*   The memory between @p input and @p input + @p length must be valid,
	*   readable, contiguous memory. However, if @p length is `0`, @p input may be
	*   `NULL`. In C++, this also must be *TriviallyCopyable*.
	*
	* @return The calculated 64-bit XXH3 hash value.
	*
	* @note
	*    seed == 0 produces the same results as @ref XXH3_64bits().
	*
	* This variant generates a custom secret on the fly based on default secret
	* altered using the @p seed value.
	*
	* While this operation is decently fast, note that it's not completely free.
	*
	* @see @ref single_shot_example "Single Shot Example" for an example.
	*/
    [CLink] public static extern XXH64_hash_t XXH3_64bits_withSeed(void* input, size_t length, XXH64_hash_t seed);

    /*!
    * The bare minimum size for a custom secret.
    *
    * @see
    *  XXH3_64bits_withSecret(), XXH3_64bits_reset_withSecret(),
    *  XXH3_128bits_withSecret(), XXH3_128bits_reset_withSecret().
    */
    const c_int XXH3_SECRET_SIZE_MIN = 136;

    /*!
    * @brief Calculates 64-bit variant of XXH3 with a custom "secret".
    *
    * @param data       The block of data to be hashed, at least @p len bytes in size.
    * @param len        The length of @p data, in bytes.
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    *
    * @return The calculated 64-bit XXH3 hash value.
    *
    * @pre
    *   The memory between @p data and @p data + @p len must be valid,
    *   readable, contiguous memory. However, if @p length is `0`, @p data may be
    *   `NULL`. In C++, this also must be *TriviallyCopyable*.
    *
    * It's possible to provide any blob of bytes as a "secret" to generate the hash.
    * This makes it more difficult for an external actor to prepare an intentional collision.
    * The main condition is that @p secretSize *must* be large enough (>= @ref XXH3_SECRET_SIZE_MIN).
    * However, the quality of the secret impacts the dispersion of the hash algorithm.
    * Therefore, the secret _must_ look like a bunch of random bytes.
    * Avoid "trivial" or structured data such as repeated sequences or a text document.
    * Whenever in doubt about the "randomness" of the blob of bytes,
    * consider employing @ref XXH3_generateSecret() instead (see below).
    * It will generate a proper high entropy secret derived from the blob of bytes.
    * Another advantage of using XXH3_generateSecret() is that
    * it guarantees that all bits within the initial blob of bytes
    * will impact every bit of the output.
    * This is not necessarily the case when using the blob of bytes directly
    * because, when hashing _small_ inputs, only a portion of the secret is employed.
    *
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
    [CLink] public static extern XXH64_hash_t XXH3_64bits_withSecret(void* data, size_t len, void* secret, size_t secretSize);

/*******   Streaming   *******/
#if !XXH_NO_STREAM
    /*
    * Streaming requires state maintenance.
    * This operation costs memory and CPU.
    * As a consequence, streaming is slower than one-shot hashing.
    * For better performance, prefer one-shot functions whenever applicable.
    */

    /*!
    * @brief The opaque state struct for the XXH3 streaming API.
    *
    * @see XXH3_state_s for details.
    * @see @ref streaming_example "Streaming Example"
    */
    typealias  XXH3_state_t = XXH3_state_s ;

    [CLink] public static extern XXH3_state_t* XXH3_createState();

    [CLink] public static extern XXH_errorcode XXH3_freeState(XXH3_state_t* statePtr);

    /*!
    * @brief Copies one @ref XXH3_state_t to another.
    *
    * @param dst_state The state to copy to.
    * @param src_state The state to copy from.
    * @pre
    *   @p dst_state and @p src_state must not be `NULL` and must not overlap.
    */
    [CLink] public static extern void XXH3_copyState(XXH3_state_t* dst_state, XXH3_state_t* src_state);

    /*!
    * @brief Resets an @ref XXH3_state_t to begin a new hash.
    *
    * @param statePtr The state struct to reset.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   - This function resets `statePtr` and generate a secret with default parameters.
    *   - Call this function before @ref XXH3_64bits_update().
    *   - Digest will be equivalent to `XXH3_64bits()`.
    *
    * @see @ref streaming_example "Streaming Example"
    *
    */
    [CLink] public static extern XXH_errorcode XXH3_64bits_reset(XXH3_state_t* statePtr);

    /*!
    * @brief Resets an @ref XXH3_state_t with 64-bit seed to begin a new hash.
    *
    * @param statePtr The state struct to reset.
    * @param seed     The 64-bit seed to alter the hash result predictably.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   - This function resets `statePtr` and generate a secret from `seed`.
    *   - Call this function before @ref XXH3_64bits_update().
    *   - Digest will be equivalent to `XXH3_64bits_withSeed()`.
    *
    * @see @ref streaming_example "Streaming Example"
    *
    */
    [CLink] public static extern XXH_errorcode XXH3_64bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed);

    /*!
    * @brief Resets an @ref XXH3_state_t with secret data to begin a new hash.
    *
    * @param statePtr The state struct to reset.
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   `secret` is referenced, it _must outlive_ the hash streaming session.
    *
    * Similar to one-shot API, `secretSize` must be >= @ref XXH3_SECRET_SIZE_MIN,
    * and the quality of produced hash values depends on secret's entropy
    * (secret's content should look like a bunch of random bytes).
    * When in doubt about the randomness of a candidate `secret`,
    * consider employing `XXH3_generateSecret()` instead (see below).
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH_errorcode XXH3_64bits_reset_withSecret(XXH3_state_t* statePtr, void* secret, size_t secretSize);

    /*!
    * @brief Consumes a block of @p input to an @ref XXH3_state_t.
    *
    * @param statePtr The state struct to update.
    * @param input The block of data to be hashed, at least @p length bytes in size.
    * @param length The length of @p input, in bytes.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    * @pre
    *   The memory between @p input and @p input + @p length must be valid,
    *   readable, contiguous memory. However, if @p length is `0`, @p input may be
    *   `NULL`. In C++, this also must be *TriviallyCopyable*.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note Call this to incrementally consume blocks of data.
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH_errorcode XXH3_64bits_update (XXH3_state_t* statePtr, void* input, size_t length);

    /*!
    * @brief Returns the calculated XXH3 64-bit hash value from an @ref XXH3_state_t.
    *
    * @param statePtr The state struct to calculate the hash from.
    *
    * @pre
    *  @p statePtr must not be `NULL`.
    *
    * @return The calculated XXH3 64-bit hash value from that state.
    *
    * @note
    *   Calling XXH3_64bits_digest() will not affect @p statePtr, so you can update,
    *   digest, and update again.
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH64_hash_t XXH3_64bits_digest (XXH3_state_t* statePtr);
    #endif /* !XXH_NO_STREAM */

    /* note : canonical representation of XXH3 is the same as XXH64
    * since they both produce XXH64_hash_t values */


    /*-**********************************************************************
    *  XXH3 128-bit variant
    ************************************************************************/

    /*!
    * @brief The return value from 128-bit hashes.
    *
    * Stored in little endian order, although the fields themselves are in native
    * endianness.
    */
    [CRepr]
    public struct XXH128_hash_t{
        public XXH64_hash_t low64;   /*!< `value & 0xFFFFFFFFFFFFFFFF` */
        public XXH64_hash_t high64;  /*!< `value >> 64` */
    }

    /*!
    * @brief Calculates 128-bit unseeded variant of XXH3 of @p data.
    *
    * @param data The block of data to be hashed, at least @p length bytes in size.
    * @param len  The length of @p data, in bytes.
    *
    * @return The calculated 128-bit variant of XXH3 value.
    *
    * The 128-bit variant of XXH3 has more strength, but it has a bit of overhead
    * for shorter inputs.
    *
    * This is equivalent to @ref XXH3_128bits_withSeed() with a seed of `0`, however
    * it may have slightly better performance due to constant propagation of the
    * defaults.
    *
    * @see XXH3_128bits_withSeed(), XXH3_128bits_withSecret(): other seeding variants
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
    [CLink] public static extern XXH128_hash_t XXH3_128bits(void* data, size_t len);

    /*! @brief Calculates 128-bit seeded variant of XXH3 hash of @p data.
    *
    * @param data The block of data to be hashed, at least @p length bytes in size.
    * @param len  The length of @p data, in bytes.
    * @param seed The 64-bit seed to alter the hash result predictably.
    *
    * @return The calculated 128-bit variant of XXH3 value.
    *
    * @note
    *    seed == 0 produces the same results as @ref XXH3_64bits().
    *
    * This variant generates a custom secret on the fly based on default secret
    * altered using the @p seed value.
    *
    * While this operation is decently fast, note that it's not completely free.
    *
    * @see XXH3_128bits(), XXH3_128bits_withSecret(): other seeding variants
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
    [CLink] public static extern XXH128_hash_t XXH3_128bits_withSeed(void* data, size_t len, XXH64_hash_t seed);

    /*!
    * @brief Calculates 128-bit variant of XXH3 with a custom "secret".
    *
    * @param data       The block of data to be hashed, at least @p len bytes in size.
    * @param len        The length of @p data, in bytes.
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    *
    * @return The calculated 128-bit variant of XXH3 value.
    *
    * It's possible to provide any blob of bytes as a "secret" to generate the hash.
    * This makes it more difficult for an external actor to prepare an intentional collision.
    * The main condition is that @p secretSize *must* be large enough (>= @ref XXH3_SECRET_SIZE_MIN).
    * However, the quality of the secret impacts the dispersion of the hash algorithm.
    * Therefore, the secret _must_ look like a bunch of random bytes.
    * Avoid "trivial" or structured data such as repeated sequences or a text document.
    * Whenever in doubt about the "randomness" of the blob of bytes,
    * consider employing @ref XXH3_generateSecret() instead (see below).
    * It will generate a proper high entropy secret derived from the blob of bytes.
    * Another advantage of using XXH3_generateSecret() is that
    * it guarantees that all bits within the initial blob of bytes
    * will impact every bit of the output.
    * This is not necessarily the case when using the blob of bytes directly
    * because, when hashing _small_ inputs, only a portion of the secret is employed.
    *
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
    [CLink] public static extern XXH128_hash_t XXH3_128bits_withSecret(void* data, size_t len, void* secret, size_t secretSize);

/*******   Streaming   *******/
#if !XXH_NO_STREAM
    /*
    * Streaming requires state maintenance.
    * This operation costs memory and CPU.
    * As a consequence, streaming is slower than one-shot hashing.
    * For better performance, prefer one-shot functions whenever applicable.
    *
    * XXH3_128bits uses the same XXH3_state_t as XXH3_64bits().
    * Use already declared XXH3_createState() and XXH3_freeState().
    *
    * All reset and streaming functions have same meaning as their 64-bit counterpart.
    */

    /*!
    * @brief Resets an @ref XXH3_state_t to begin a new hash.
    *
    * @param statePtr The state struct to reset.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   - This function resets `statePtr` and generate a secret with default parameters.
    *   - Call it before @ref XXH3_128bits_update().
    *   - Digest will be equivalent to `XXH3_128bits()`.
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH_errorcode XXH3_128bits_reset(XXH3_state_t* statePtr);

    /*!
    * @brief Resets an @ref XXH3_state_t with 64-bit seed to begin a new hash.
    *
    * @param statePtr The state struct to reset.
    * @param seed     The 64-bit seed to alter the hash result predictably.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   - This function resets `statePtr` and generate a secret from `seed`.
    *   - Call it before @ref XXH3_128bits_update().
    *   - Digest will be equivalent to `XXH3_128bits_withSeed()`.
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH_errorcode XXH3_128bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed);
    /*!
    * @brief Resets an @ref XXH3_state_t with secret data to begin a new hash.
    *
    * @param statePtr   The state struct to reset.
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * `secret` is referenced, it _must outlive_ the hash streaming session.
    * Similar to one-shot API, `secretSize` must be >= @ref XXH3_SECRET_SIZE_MIN,
    * and the quality of produced hash values depends on secret's entropy
    * (secret's content should look like a bunch of random bytes).
    * When in doubt about the randomness of a candidate `secret`,
    * consider employing `XXH3_generateSecret()` instead (see below).
    *
    * @see @ref streaming_example "Streaming Example"
    */
    [CLink] public static extern XXH_errorcode XXH3_128bits_reset_withSecret(XXH3_state_t* statePtr, void* secret, size_t secretSize);

    /*!
    * @brief Consumes a block of @p input to an @ref XXH3_state_t.
    *
    * Call this to incrementally consume blocks of data.
    *
    * @param statePtr The state struct to update.
    * @param input The block of data to be hashed, at least @p length bytes in size.
    * @param length The length of @p input, in bytes.
    *
    * @pre
    *   @p statePtr must not be `NULL`.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @note
    *   The memory between @p input and @p input + @p length must be valid,
    *   readable, contiguous memory. However, if @p length is `0`, @p input may be
    *   `NULL`. In C++, this also must be *TriviallyCopyable*.
    *
    */
    [CLink] public static extern XXH_errorcode XXH3_128bits_update (XXH3_state_t* statePtr, void* input, size_t length);

    /*!
    * @brief Returns the calculated XXH3 128-bit hash value from an @ref XXH3_state_t.
    *
    * @param statePtr The state struct to calculate the hash from.
    *
    * @pre
    *  @p statePtr must not be `NULL`.
    *
    * @return The calculated XXH3 128-bit hash value from that state.
    *
    * @note
    *   Calling XXH3_128bits_digest() will not affect @p statePtr, so you can update,
    *   digest, and update again.
    *
    */
    [CLink] public static extern XXH128_hash_t XXH3_128bits_digest (XXH3_state_t* statePtr);
#endif /* !XXH_NO_STREAM */

    /* Following helper functions make it possible to compare XXH128_hast_t values.
    * Since XXH128_hash_t is a structure, this capability is not offered by the language.
    * Note: For better performance, these functions can be inlined using XXH_INLINE_ALL */

    /*!
    * @brief Check equality of two XXH128_hash_t values
    *
    * @param h1 The 128-bit hash value.
    * @param h2 Another 128-bit hash value.
    *
    * @return `1` if `h1` and `h2` are equal.
    * @return `0` if they are not.
    */
    [CLink] public static extern int XXH128_isEqual(XXH128_hash_t h1, XXH128_hash_t h2);

    /*!
    * @brief Compares two @ref XXH128_hash_t
    *
    * This comparator is compatible with stdlib's `qsort()`/`bsearch()`.
    *
    * @param h128_1 Left-hand side value
    * @param h128_2 Right-hand side value
    *
    * @return >0 if @p h128_1  > @p h128_2
    * @return =0 if @p h128_1 == @p h128_2
    * @return <0 if @p h128_1  < @p h128_2
    */
    [CLink] public static extern int XXH128_cmp(void* h128_1, void* h128_2);

    /*******   Canonical representation   *******/
    public struct XXH128_canonical_t {
        c_uchar[sizeof(XXH128_hash_t)] digest;
    }

    /*!
    * @brief Converts an @ref XXH128_hash_t to a big endian @ref XXH128_canonical_t.
    *
    * @param dst  The @ref XXH128_canonical_t pointer to be stored to.
    * @param hash The @ref XXH128_hash_t to be converted.
    *
    * @pre
    *   @p dst must not be `NULL`.
    * @see @ref canonical_representation_example "Canonical Representation Example"
    */
    [CLink] public static extern void XXH128_canonicalFromHash(XXH128_canonical_t* dst, XXH128_hash_t hash);

    /*!
    * @brief Converts an @ref XXH128_canonical_t to a native @ref XXH128_hash_t.
    *
    * @param src The @ref XXH128_canonical_t to convert.
    *
    * @pre
    *   @p src must not be `NULL`.
    *
    * @return The converted hash.
    * @see @ref canonical_representation_example "Canonical Representation Example"
    */
    [CLink] public static extern XXH128_hash_t XXH128_hashFromCanonical(XXH128_canonical_t* src);
#endif  /* !XXH_NO_XXH3 */

#endif  /* XXH_NO_LONG_LONG */

    /* ****************************************************************************
    * This section contains declarations which are not guaranteed to remain stable.
    * They may change in future versions, becoming incompatible with a different
    * version of the library.
    * These declarations should only be used with static linking.
    * Never use them in association with dynamic linking!
    ***************************************************************************** */

    /*
    * These definitions are only present to allow static allocation
    * of XXH states, on stack or in a struct, for example.
    * Never **ever** access their members directly.
    */

    /*!
    * @internal
    * @brief Structure for XXH32 streaming API.
    *
    * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
    * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
    * an opaque type. This allows fields to safely be changed.
    *
    * Typedef'd to @ref XXH32_state_t.
    * Do not access the members of this struct directly.
    * @see XXH64_state_s, XXH3_state_s
    */
    [CRepr]
    public struct XXH32_state_s {
        XXH32_hash_t total_len_32; /*!< Total length hashed, modulo 2^32 */
        XXH32_hash_t large_len;    /*!< Whether the hash is >= 16 (handles @ref total_len_32 overflow) */
        XXH32_hash_t[4] acc;       /*!< Accumulator lanes */
        c_uchar[16] buffer;  /*!< Internal buffer for partial reads. */
        XXH32_hash_t bufferedSize; /*!< Amount of data in @ref buffer */
        XXH32_hash_t reserved;     /*!< Reserved field. Do not read nor write to it. */
    }   /* typedef'd to XXH32_state_t */

#if !XXH_NO_LONG_LONG  /* defined when there is no 64-bit support */
    /*!
    * @internal
    * @brief Structure for XXH64 streaming API.
    *
    * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
    * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
    * an opaque type. This allows fields to safely be changed.
    *
    * Typedef'd to @ref XXH64_state_t.
    * Do not access the members of this struct directly.
    * @see XXH32_state_s, XXH3_state_s
    */
	[CRepr]
	struct XXH64_state_s
	{
		XXH64_hash_t total_len; /*!< Total length hashed. This is always 64-bit. */
		XXH64_hash_t[4] acc; /*!< Accumulator lanes */
		c_uchar[32] buffer; /*!< Internal buffer for partial reads.. */
		XXH32_hash_t bufferedSize; /*!< Amount of data in @ref buffer */
		XXH32_hash_t reserved32; /*!< Reserved field, needed for padding anyways*/
		XXH64_hash_t reserved64; /*!< Reserved field. Do not read or write to it. */
	} /* typedef'd to XXH64_state_t */

#if !XXH_NO_XXH3

    /*!
    * @internal
    * @brief The size of the internal XXH3 buffer.
    *
    * This is the optimal update size for incremental hashing.
    *
    * @see XXH3_64b_update(), XXH3_128b_update().
    */
    const c_int XXH3_INTERNALBUFFER_SIZE = 256;

    /*!
    * @def XXH3_SECRET_DEFAULT_SIZE
    * @brief Default Secret's size
    *
    * This is the size of internal XXH3_kSecret
    * and is needed by XXH3_generateSecret_fromSeed().
    *
    * Not to be confused with @ref XXH3_SECRET_SIZE_MIN.
    */
    const c_int XXH3_SECRET_DEFAULT_SIZE = 192;

    /*!
    * @internal
    * @brief Structure for XXH3 streaming API.
    *
    * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
    * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined.
    * Otherwise it is an opaque type.
    * Never use this definition in combination with dynamic library.
    * This allows fields to safely be changed in the future.
    *
    * @note ** This structure has a strict alignment requirement of 64 bytes!! **
    * Do not allocate this with `malloc()` or `new`,
    * it will not be sufficiently aligned.
    * Use @ref XXH3_createState() and @ref XXH3_freeState(), or stack allocation.
    *
    * Typedef'd to @ref XXH3_state_t.
    * Do never access the members of this struct directly.
    *
    * @see XXH3_INITSTATE() for stack initialization.
    * @see XXH3_createState(), XXH3_freeState().
    * @see XXH32_state_s, XXH64_state_s
    */
    [CRepr]
    public struct XXH3_state_s {
        // XXH_ALIGN_MEMBER(64, XXH64_hash_t[8] acc);
        // /*!< The 8 accumulators. See @ref XXH32_state_s::acc and @ref XXH64_state_s::acc */
        // XXH_ALIGN_MEMBER(64, c_uchar[XXH3_SECRET_DEFAULT_SIZE] customSecret);
        // /*!< Used to store a custom secret generated from a seed. */
        // XXH_ALIGN_MEMBER(64, c_uchar[XXH3_INTERNALBUFFER_SIZE] buffer);
        /*!< The internal buffer. @see XXH32_state_s::mem32 */
        XXH32_hash_t bufferedSize;
        /*!< The amount of memory in @ref buffer, @see XXH32_state_s::memsize */
        XXH32_hash_t useSeed;
        /*!< Reserved field. Needed for padding on 64-bit. */
        size_t nbStripesSoFar;
        /*!< Number or stripes processed. */
        XXH64_hash_t totalLen;
        /*!< Total length hashed. 64-bit even on 32-bit targets. */
        size_t nbStripesPerBlock;
        /*!< Number of stripes per block. */
        size_t secretLimit;
        /*!< Size of @ref customSecret or @ref extSecret */
        XXH64_hash_t seed;
        /*!< Seed for _withSeed variants. Must be zero otherwise, @see XXH3_INITSTATE() */
        XXH64_hash_t reserved64;
        /*!< Reserved field. */
        c_uchar* extSecret;
        /*!< Reference to an external secret for the _withSecret variants, NULL
                *   for other variants. */
        /* note: there may be some padding at the end due to alignment on 64 bytes */
    } /* typedef'd to XXH3_state_t */

    /*!
    * @brief Initializes a stack-allocated `XXH3_state_s`.
    *
    * When the @ref XXH3_state_t structure is merely emplaced on stack,
    * it should be initialized with XXH3_INITSTATE() or a memset()
    * in case its first reset uses XXH3_NNbits_reset_withSeed().
    * This init can be omitted if the first reset uses default or _withSecret mode.
    * This operation isn't necessary when the state is created with XXH3_createState().
    * Note that this doesn't prepare the state for a streaming operation,
    * it's still necessary to use XXH3_NNbits_reset*() afterwards.
    */
    // #define XXH3_INITSTATE(XXH3_state_ptr)                       \
    //     do {                                                     \
    //         XXH3_state_t* tmp_xxh3_state_ptr = (XXH3_state_ptr); \
    //         tmp_xxh3_state_ptr->seed = 0;                        \
    //         tmp_xxh3_state_ptr->extSecret = NULL;                \
    //     } while(0)


    /*!
    * @brief Calculates the 128-bit hash of @p data using XXH3.
    *
    * @param data The block of data to be hashed, at least @p len bytes in size.
    * @param len  The length of @p data, in bytes.
    * @param seed The 64-bit seed to alter the hash's output predictably.
    *
    * @pre
    *   The memory between @p data and @p data + @p len must be valid,
    *   readable, contiguous memory. However, if @p len is `0`, @p data may be
    *   `NULL`. In C++, this also must be *TriviallyCopyable*.
    *
    * @return The calculated 128-bit XXH3 value.
    *
    * @see @ref single_shot_example "Single Shot Example" for an example.
    */
    [CLink] public static extern XXH128_hash_t XXH128(void* data, size_t len, XXH64_hash_t seed);


    /* ===   Experimental API   === */
    /* Symbols defined below must be considered tied to a specific library version. */

    /*!
    * @brief Derive a high-entropy secret from any user-defined content, named customSeed.
    *
    * @param secretBuffer    A writable buffer for derived high-entropy secret data.
    * @param secretSize      Size of secretBuffer, in bytes.  Must be >= XXH3_SECRET_SIZE_MIN.
    * @param customSeed      A user-defined content.
    * @param customSeedSize  Size of customSeed, in bytes.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * The generated secret can be used in combination with `*_withSecret()` functions.
    * The `_withSecret()` variants are useful to provide a higher level of protection
    * than 64-bit seed, as it becomes much more difficult for an external actor to
    * guess how to impact the calculation logic.
    *
    * The function accepts as input a custom seed of any length and any content,
    * and derives from it a high-entropy secret of length @p secretSize into an
    * already allocated buffer @p secretBuffer.
    *
    * The generated secret can then be used with any `*_withSecret()` variant.
    * The functions @ref XXH3_128bits_withSecret(), @ref XXH3_64bits_withSecret(),
    * @ref XXH3_128bits_reset_withSecret() and @ref XXH3_64bits_reset_withSecret()
    * are part of this list. They all accept a `secret` parameter
    * which must be large enough for implementation reasons (>= @ref XXH3_SECRET_SIZE_MIN)
    * _and_ feature very high entropy (consist of random-looking bytes).
    * These conditions can be a high bar to meet, so @ref XXH3_generateSecret() can
    * be employed to ensure proper quality.
    *
    * @p customSeed can be anything. It can have any size, even small ones,
    * and its content can be anything, even "poor entropy" sources such as a bunch
    * of zeroes. The resulting `secret` will nonetheless provide all required qualities.
    *
    * @pre
    *   - @p secretSize must be >= @ref XXH3_SECRET_SIZE_MIN
    *   - When @p customSeedSize > 0, supplying NULL as customSeed is undefined behavior.
    *
    * Example code:
    * @code{.c}
    *    #include <stdio.h>
    *    #include <stdlib.h>
    *    #include <string.h>
    *    #define XXH_STATIC_LINKING_ONLY // expose unstable API
    *    #include "xxhash.h"
    *    // Hashes argv[2] using the entropy from argv[1].
    *    int main(int argc, char* argv[])
    *    {
    *        char secret[XXH3_SECRET_SIZE_MIN];
    *        if (argv != 3) { return 1; }
    *        XXH3_generateSecret(secret, sizeof(secret), argv[1], strlen(argv[1]));
    *        XXH64_hash_t h = XXH3_64bits_withSecret(
    *             argv[2], strlen(argv[2]),
    *             secret, sizeof(secret)
    *        );
    *        printf("%016llx\n", (c_ulong long) h);
    *    }
    * @endcode
    */
    [CLink] public static extern XXH_errorcode XXH3_generateSecret(void* secretBuffer, size_t secretSize, void* customSeed, size_t customSeedSize);

    /*!
    * @brief Generate the same secret as the _withSeed() variants.
    *
    * @param secretBuffer A writable buffer of @ref XXH3_SECRET_DEFAULT_SIZE bytes
    * @param seed         The 64-bit seed to alter the hash result predictably.
    *
    * The generated secret can be used in combination with
    *`*_withSecret()` and `_withSecretandSeed()` variants.
    *
    * Example C++ `std::string` hash class:
    * @code{.cpp}
    *    #include <string>
    *    #define XXH_STATIC_LINKING_ONLY // expose unstable API
    *    #include "xxhash.h"
    *    // Slow, seeds each time
    *    class HashSlow {
    *        XXH64_hash_t seed;
    *    public:
    *        HashSlow(XXH64_hash_t s) : seed{s} {}
    *        size_t operator()(std::string& x) {
    *            return size_t{XXH3_64bits_withSeed(x.c_str(), x.length(), seed)}
    *        }
    *    }
    *    // Fast, caches the seeded secret for future uses.
    *    class HashFast {
    *        c_uchar secret[XXH3_SECRET_DEFAULT_SIZE];
    *    public:
    *        HashFast(XXH64_hash_t s) {
    *            XXH3_generateSecret_fromSeed(secret, seed);
    *        }
    *        size_t operator()(std::string& x) {
    *            return size_t{
    *                XXH3_64bits_withSecret(x.c_str(), x.length(), secret, sizeof(secret))
    *            }
    *        }
    *    }
    * @endcode
    */
    [CLink] public static extern void XXH3_generateSecret_fromSeed(void* secretBuffer, XXH64_hash_t seed);

    /*!
    * @brief Maximum size of "short" key in bytes.
    */
    const c_int XXH3_MIDSIZE_MAX = 240;

    /*!
    * @brief Calculates 64/128-bit seeded variant of XXH3 hash of @p data.
    *
    * @param data       The block of data to be hashed, at least @p len bytes in size.
    * @param len        The length of @p data, in bytes.
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    * @param seed       The 64-bit seed to alter the hash result predictably.
    *
    * These variants generate hash values using either:
    * - @p seed for "short" keys (< @ref XXH3_MIDSIZE_MAX = 240 bytes)
    * - @p secret for "large" keys (>= @ref XXH3_MIDSIZE_MAX).
    *
    * This generally benefits speed, compared to `_withSeed()` or `_withSecret()`.
    * `_withSeed()` has to generate the secret on the fly for "large" keys.
    * It's fast, but can be perceptible for "not so large" keys (< 1 KB).
    * `_withSecret()` has to generate the masks on the fly for "small" keys,
    * which requires more instructions than _withSeed() variants.
    * Therefore, _withSecretandSeed variant combines the best of both worlds.
    *
    * When @p secret has been generated by XXH3_generateSecret_fromSeed(),
    * this variant produces *exactly* the same results as `_withSeed()` variant,
    * hence offering only a pure speed benefit on "large" input,
    * by skipping the need to regenerate the secret for every large input.
    *
    * Another usage scenario is to hash the secret to a 64-bit hash value,
    * for example with XXH3_64bits(), which then becomes the seed,
    * and then employ both the seed and the secret in _withSecretandSeed().
    * On top of speed, an added benefit is that each bit in the secret
    * has a 50% chance to swap each bit in the output, via its impact to the seed.
    *
    * This is not guaranteed when using the secret directly in "small data" scenarios,
    * because only portions of the secret are employed for small data.
    */
    [CLink] public static extern XXH64_hash_t XXH3_64bits_withSecretandSeed(void* data, size_t len, void* secret, size_t secretSize, XXH64_hash_t seed);

    /*!
    * @brief Calculates 128-bit seeded variant of XXH3 hash of @p data.
    *
    * @param input      The memory segment to be hashed, at least @p len bytes in size.
    * @param length     The length of @p data, in bytes.
    * @param secret     The secret used to alter hash result predictably.
    * @param secretSize The length of @p secret, in bytes (must be >= XXH3_SECRET_SIZE_MIN)
    * @param seed64     The 64-bit seed to alter the hash result predictably.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @see XXH3_64bits_withSecretandSeed(): contract is the same.
    */
    [CLink] public static extern XXH128_hash_t XXH3_128bits_withSecretandSeed(void* input, size_t length, void* secret, size_t secretSize, XXH64_hash_t seed64);

#if !XXH_NO_STREAM
    /*!
    * @brief Resets an @ref XXH3_state_t with secret data to begin a new hash.
    *
    * @param statePtr   A pointer to an @ref XXH3_state_t allocated with @ref XXH3_createState().
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    * @param seed64     The 64-bit seed to alter the hash result predictably.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @see XXH3_64bits_withSecretandSeed(). Contract is identical.
    */
    [CLink] public static extern XXH_errorcode XXH3_64bits_reset_withSecretandSeed(XXH3_state_t* statePtr, void* secret, size_t secretSize, XXH64_hash_t seed64);

    /*!
    * @brief Resets an @ref XXH3_state_t with secret data to begin a new hash.
    *
    * @param statePtr   A pointer to an @ref XXH3_state_t allocated with @ref XXH3_createState().
    * @param secret     The secret data.
    * @param secretSize The length of @p secret, in bytes.
    * @param seed64     The 64-bit seed to alter the hash result predictably.
    *
    * @return @ref XXH_OK on success.
    * @return @ref XXH_ERROR on failure.
    *
    * @see XXH3_64bits_withSecretandSeed(). Contract is identical.
    *
    * Note: there was a bug in an earlier version of this function (<= v0.8.2)
    * that would make it generate an incorrect hash value
    * when @p seed == 0 and @p length < XXH3_MIDSIZE_MAX
    * and @p secret is different from XXH3_generateSecret_fromSeed().
    * As stated in the contract, the correct hash result must be
    * the same as XXH3_128bits_withSeed() when @p length <= XXH3_MIDSIZE_MAX.
    * Results generated by this older version are wrong, hence not comparable.
    */
    [CLink] public static extern XXH_errorcode XXH3_128bits_reset_withSecretandSeed(XXH3_state_t* statePtr, void* secret, size_t secretSize, XXH64_hash_t seed64);

#endif /* !XXH_NO_STREAM */

#endif  /* !XXH_NO_XXH3 */

#endif  /* !XXH_NO_LONG_LONG */
}