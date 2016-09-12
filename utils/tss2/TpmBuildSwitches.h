/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: TpmBuildSwitches.h 684 2016-07-18 21:22:01Z kgoldman $	*/
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

/* rev 122 */

// 5.12	TpmBuildSwitches.h

// This file contains the build switches. This contains switches for multiple versions of the crypto-library so some may not apply to your environment.
#ifndef _TPM_BUILD_SWITCHES_H
#define _TPM_BUILD_SWITCHES_H
#define SIMULATION
#define FIPS_COMPLIANT
// Define TABLE_DRIVEN_DISPATCH to use tables rather than case statements for command dispatch and handle unmarshaling
#define TABLE_DRIVEN_DISPATCH
#ifndef RSA_KEY_SIEVE
// Remove comment on following line to enable the generation of RSA primes using a sieve.
// #define RSA_KEY_SIEVE
#endif
// Define the alignment macro appropriate for the build environment For MS C compiler
#define ALIGN_TO(boundary)  __declspec(align(boundary))
// For ISO 9899:2011
// #define ALIGN_TO(boundary)    _Alignas(boundary)
// This switch enables the RNG state save and restore
#undef  _DRBG_STATE_SAVE
#define _DRBG_STATE_SAVE        // Comment this out if no state save is wanted
// Switch added to support packed lists that leave out space assocaited with unimplemented commands. Comment this out to use linear lists.
// NOTE:	if vendor specific commands are presnet, the associated list is always in compressed form.
#define COMPRESSED_LISTS
// Set the alignment size for the crypto. It would be nice to set this according to macros automatically defined by the build environment, but that doesn't seem possible because there isn't any simple set for that. So, this is just a plugged value. Your compiler should complain if this alignment isn't possible.
// NOTE:	this value can be set at the command line or just plugged in here.
#ifdef CRYPTO_ALIGN_16
#   define CRYPTO_ALIGNMENT     16
#elif defined CRYPTO_ALIGN_8
#   define CRYPTO_ALIGNMENT     8
#elif defined CRYPTO_ALIGN_2
#   define  CRYPTO_ALIGNMENT    2
#elif defined CRTYPO_ALIGN_1
#   define  CRYPTO_ALIGNMENT    1
#else
#   define CRYPTO_ALIGNMENT     4    // For 32-bit builds
#endif
#define CRYPTO_ALIGNED	// kgold
// #define CRYPTO_ALIGNED  ALIGN_TO(CRYPTO_ALIGNMENT)
#ifdef  _MSC_VER

// This macro is used to handle LIB_EXPORT of function and variable names in lieu of a .def
// file. Visual Studio requires that functions be explicity exported and imported.

#   define LIB_EXPORT __declspec(dllexport) // VS compatible version
#   define LIB_IMPORT __declspec(dllimport)

// This is defined to indicate a function that does not return. Microsoft compilers do not support
// the _Noretrun() function parameter.

#   define NORETURN  __declspec(noreturn)
#   define INLINE  __inline
#ifdef SELF_TEST
#pragma comment(lib, "algorithmtests.lib")
#endif
#endif // _MSC_VER

// The following definitions are used if they have not already been defined. The defaults for these
// settings are compatible with ISO/IEC 9899:2011 (E)

#ifndef LIB_EXPORT
#   define LIB_EXPORT
#   define LIB_IMPORT
#endif
#ifndef NORETURN
/* #   define NORETURN _Noreturn */
/* for gcc - kgold */
#   define NORETURN
#endif
#ifndef INLINE
#   define  INLINE  inline
#endif
#ifndef NOT_REFERENCED
#   define NOT_REFERENCED(x)   ((void) (x))
#endif
// This definition forces the no-debug setting for the compile unless DEBUG is explicity set.
#if !defined DEBUG && !defined NDEBUG
#   define NDEBUG
#endif
// The switches in this group can only be enabled when running a simulation
#ifdef SIMULATION
#   define RSA_KEY_CACHE
#   ifdef DEBUG
// This provides fixed seeding of the RNG when doing debug on a simulator. This should allow consistent results on test runs as long as the input parameters to the functions remains the same.
#       define TPM_RNG_FOR_DEBUG
#   endif
#else
#   undef RSA_KEY_CACHE
#   undef TPM_RNG_FOR_DEBUG
#endif  // SIMULATION
#endif // _TPM_BUILD_SWITCHES_H
