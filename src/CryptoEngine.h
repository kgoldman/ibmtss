/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptoEngine.h 684 2016-07-18 21:22:01Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2012-2015				*/
/*										*/
/********************************************************************************/

/* rev 124 */

// B.3.1.	Introduction

// This file contains constant definition shared by CryptUtil() and the parts of the Crypto Engine.

#ifndef _CRYPT_PRI_H
#define _CRYPT_PRI_H

#include    <stddef.h>
#include    <tss2/TpmBuildSwitches.h>
#include    <tss2/BaseTypes.h>
#include    "TpmError.h"
#include    "swap.h"
#include    <tss2/Implementation.h>
#include    <tss2/TPM_Types.h>
#include    "bool.h"
#include    "Platform.h"

#ifndef NULL
#define NULL    0
#endif

typedef UINT16  NUMBYTES;       // When a size is a number of bytes
typedef UINT32  NUMDIGITS;      // When a size is a number of "digits"

// B.3.2.	General Purpose Macros

#ifndef MAX
#   define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#   define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#define BITS_TO_BYTES(bits)     (((bits) + 7) / 8)

// This is the definition of a bit array with one bit per algorithm

typedef BYTE    ALGORITHM_VECTOR[(ALG_LAST_VALUE + 7) / 8];

// B.3.3.	Self-test

// This structure is used to contain self-test tracking information for the crypto engine. Each of
// the major modules is given a 32-bit value in which it may maintain its own self test
// information. The convention for this state is that when all of the bits in this structure are 0,
// all functions need to be tested.

typedef struct {
    UINT32      rng;
    UINT32      hash;
    UINT32      sym;
#ifdef TPM_ALG_RSA
    UINT32      rsa;
#endif
#ifdef  TPM_ALG_ECC
    UINT32      ecc;
#endif
} CRYPTO_SELF_TEST_STATE;

// B.3.4.	Hash-related Structures

typedef struct {
    const TPM_ALG_ID      alg;
    const NUMBYTES        digestSize;
    const NUMBYTES        blockSize;
    const NUMBYTES        derSize;
    const BYTE            der[20];
} HASH_INFO;

// This value will change with each implementation. The value of 16 is used to account for any slop
// in the context values. The overall size needs to be as large as any of the hash contexts. The
// structure needs to start on an alignment boundary and be an even multiple of the alignment

#define ALIGNED_SIZE(x, b) ((((x) + (b) - 1) / (b)) * (b))
#define MAX_HASH_STATE_SIZE ((2 * MAX_HASH_BLOCK_SIZE) + 16)
#define MAX_HASH_STATE_SIZE_ALIGNED					\
    ALIGNED_SIZE(MAX_HASH_STATE_SIZE, CRYPTO_ALIGNMENT)

// This is an byte array that will hold any of the hash contexts.

typedef CRYPTO_ALIGNED BYTE ALIGNED_HASH_STATE[MAX_HASH_STATE_SIZE_ALIGNED];

// Macro to align an address to the next higher size

#define AlignPointer(address, align)				\
    ((((intptr_t)&(address)) + (align - 1)) & ~(align - 1))
	// Macro to test alignment
#define IsAddressAligned(address, align)				\
    (((intptr_t)(address) & (align - 1)) == 0)

// This is the structure that is used for passing a context into the hashing functions. It should be
// the same size as the function context used within the hashing functions. This is checked when the
// hash function is initialized. This version uses a new layout for the contexts and a different
// definition. The state buffer is an array of HASH_UNIT values so that a decent compiler will put
// the structure on a HASH_UNIT boundary. If the structure is not properly aligned, the code that
// manipulates the structure will copy to a properly aligned structure before it is used and copy
// the result back. This just makes things slower.

typedef struct _HASH_STATE
{
    ALIGNED_HASH_STATE       state;
    TPM_ALG_ID               hashAlg;
} CPRI_HASH_STATE, *PCPRI_HASH_STATE;

extern const HASH_INFO   g_hashData[HASH_COUNT + 1];

// This is for the external hash state. This implementation assumes that the size of the exported
// hash state is no larger than the internal hash state. There is a compile-time check to make sure
// that this is true.

typedef struct {
    ALIGNED_HASH_STATE      buffer;
    TPM_ALG_ID              hashAlg;
} EXPORT_HASH_STATE;

typedef enum {
    IMPORT_STATE,       // Converts externally formatted state to internal
    EXPORT_STATE        // Converts internal formatted state to external
} IMPORT_EXPORT;

// Values and structures for the random number generator. These values are defined in this header
// file so that the size of the RNG state can be known to TPM.lib. This allows the allocation of
// some space in NV memory for the state to be stored on an orderly shutdown. The GET_PUT enum is
// used by _cpri__DrbgGetPutState() to indicate the direction of data flow.

typedef enum {
    GET_STATE,      // Get the state to save to NV
    PUT_STATE       // Restore the state from NV
} GET_PUT;

// The DRBG based on a symmetric block cipher is defined by three values,
//    a)	the key size
//    b)	the block size (the IV size)
//    c)	the symmetric algorithm

#define DRBG_KEY_SIZE_BITS      MAX_AES_KEY_BITS
#define DRBG_IV_SIZE_BITS       (MAX_AES_BLOCK_SIZE_BYTES * 8)
#define DRBG_ALGORITHM          TPM_ALG_AES
#if ((DRBG_KEY_SIZE_BITS % 8) != 0) || ((DRBG_IV_SIZE_BITS % 8) != 0)
#error "Key size and IV for DRBG must be even multiples of 8"
#endif
#if (DRBG_KEY_SIZE_BITS % DRBG_IV_SIZE_BITS) != 0
#error "Key size for DRBG must be even multiple of the cypher block size"
#endif

typedef UINT32    DRBG_SEED[(DRBG_KEY_SIZE_BITS + DRBG_IV_SIZE_BITS) / 32];
typedef struct {
    UINT64      reseedCounter;
    UINT32      magic;
    DRBG_SEED   seed; // contains the key and IV for the counter mode DRBG
    UINT32      lastValue[4];   // used when the TPM does continuous self-test
    // for FIPS compliance of DRBG
} DRBG_STATE, *pDRBG_STATE;

// B.3.5.	Asymmetric Structures and Values

#ifdef TPM_ALG_ECC

// B.3.5.1.	ECC-related Structures

// This structure replicates the structure definition in TPM_Types.h. It is duplicated to avoid
// inclusion of all of TPM_Types.h This structure is similar to the RSA_KEY structure below. The
// purpose of these structures is to reduce the overhead of a function call and to make the code
// less dependent on key types as much as possible.

typedef struct {
    UINT32                 curveID;       // The curve identifier
    TPMS_ECC_POINT        *publicPoint;   // Pointer to the public point
    TPM2B_ECC_PARAMETER   *privateKey;    // Pointer to the private key
} ECC_KEY;
#endif // TPM_ALG_ECC

#ifdef TPM_ALG_RSA

// B.3.5.2.	RSA-related Structures

// This structure is a succinct representation of the cryptographic components of an RSA key.

typedef struct {
    UINT32        exponent;      // The public exponent pointer
    TPM2B        *publicKey;     // Pointer to the public modulus
    TPM2B        *privateKey;    // The private exponent (not a prime)
} RSA_KEY;

#endif // TPM_ALG_RSA

// B.3.6.	Miscellaneous

#ifdef TPM_ALG_RSA
#   ifdef TPM_ALG_ECC
#       if   MAX_RSA_KEY_BYTES > MAX_ECC_KEY_BYTES
#           define  MAX_NUMBER_SIZE         MAX_RSA_KEY_BYTES
#       else
#           define  MAX_NUMBER_SIZE         MAX_ECC_KEY_BYTES
#       endif
#   else // RSA but no ECC
#       define MAX_NUMBER_SIZE              MAX_RSA_KEY_BYTES
#   endif
#elif defined TPM_ALG_ECC
#   define MAX_NUMBER_SIZE                 MAX_ECC_KEY_BYTES
#else
#   error No assymmetric algorithm implemented.
#endif

typedef INT16     CRYPT_RESULT;

#define CRYPT_RESULT_MIN    INT16_MIN
#define CRYPT_RESULT_MAX    INT16_MAX

// < 0	recoverable error
//   0	success
//   > 0	command specific return value (generally a digest size)

#define CRYPT_FAIL          ((CRYPT_RESULT)  1)
#define CRYPT_SUCCESS       ((CRYPT_RESULT)  0)
#define CRYPT_NO_RESULT     ((CRYPT_RESULT) -1)
#define CRYPT_SCHEME        ((CRYPT_RESULT) -2)
#define CRYPT_PARAMETER     ((CRYPT_RESULT) -3)
#define CRYPT_UNDERFLOW     ((CRYPT_RESULT) -4)
#define CRYPT_POINT         ((CRYPT_RESULT) -5)
#define CRYPT_CANCEL        ((CRYPT_RESULT) -6)

typedef UINT64              HASH_CONTEXT[MAX_HASH_STATE_SIZE/sizeof(UINT64)];

#include    "CpriCryptPri_fp.h"
#ifdef  TPM_ALG_ECC
#   include "CpriDataEcc.h"
#   include "CpriECC_fp.h"
#endif

#include    "MathFunctions_fp.h"
#include    "CpriRNG_fp.h"
#include    "tss2/CpriHash_fp.h"
#include    "CpriSym_fp.h"
#ifdef  TPM_ALG_RSA
#   include    "CpriRSA_fp.h"
#   ifdef RSA_KEY_SIEVE
#       include "RsaKeySieve_fp.h"
#   endif
#endif

#endif // !_CRYPT_PRI_H

