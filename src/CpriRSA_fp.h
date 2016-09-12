/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriRSA_fp.h 55 2015-02-05 22:03:16Z kgoldman $		*/
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

/* rev 119 */

#ifndef CPRIRSA_FP_H
#define CPRIRSA_FP_H

LIB_EXPORT CRYPT_RESULT
_cpri__TestKeyRSA(
		  TPM2B           *d,             // OUT: the address to receive the private
		  //     exponent
		  UINT32           exponent,      // IN: the public modulu
		  TPM2B           *publicKey,     // IN/OUT: an input if only one prime is
		  //     provided. an output if both primes are
		  //     provided
		  TPM2B           *prime1,        // IN: a first prime
		  TPM2B           *prime2         // IN: an optional second prime
		  );
LIB_EXPORT BOOL
_cpri__RsaStartup(
		  void
		  );
LIB_EXPORT CRYPT_RESULT
_cpri__EncryptRSA(
		  UINT32          *cOutSize,      // OUT: the size of the encrypted data
		  BYTE            *cOut,          // OUT: the encrypted data
		  RSA_KEY         *key,           // IN: the key to use for encryption
		  TPM_ALG_ID       padType,       // IN: the type of padding
		  UINT32           dInSize,       // IN: the amount of data to encrypt
		  BYTE            *dIn,           // IN: the data to encrypt
		  TPM_ALG_ID       hashAlg,       // IN: in case this is needed
		  const char      *label          // IN: in case it is needed
		  );
LIB_EXPORT CRYPT_RESULT
_cpri__DecryptRSA(
		  UINT32          *dOutSize,      // OUT: the size of the decrypted data
		  BYTE            *dOut,          // OUT: the decrypted data
		  RSA_KEY         *key,           // IN: the key to use for decryption
		  TPM_ALG_ID       padType,       // IN: the type of padding
		  UINT32           cInSize,       // IN: the amount of data to decrypt
		  BYTE            *cIn,           // IN: the data to decrypt
		  TPM_ALG_ID       hashAlg,       // IN: in case this is needed for the scheme
		  const char      *label          // IN: in case it is needed for the scheme
		  );
LIB_EXPORT CRYPT_RESULT
_cpri__SignRSA(
	       UINT32          *sigOutSize,    // OUT: size of signature
	       BYTE            *sigOut,        // OUT: signature
	       RSA_KEY         *key,           // IN: key to use
	       TPM_ALG_ID       scheme,        // IN: the scheme to use
	       TPM_ALG_ID       hashAlg,       // IN: hash algorithm for PKSC1v1_5
	       UINT32           hInSize,       // IN: size of digest to be signed
	       BYTE            *hIn            // IN: digest buffer
	       );
LIB_EXPORT CRYPT_RESULT
_cpri__ValidateSignatureRSA(
			    RSA_KEY         *key,           // IN: key to use
			    TPM_ALG_ID       scheme,        // IN: the scheme to use
			    TPM_ALG_ID       hashAlg,       // IN: hash algorithm
			    UINT32           hInSize,       // IN: size of digest to be checked
			    BYTE            *hIn,           // IN: digest buffer
			    UINT32           sigInSize,     // IN: size of signature
			    BYTE            *sigIn,         // IN: signature
			    UINT16           saltSize       // IN: salt size for PSS
			    );
LIB_EXPORT CRYPT_RESULT
_cpri__GenerateKeyRSA(
		      TPM2B           *n,             // OUT: The public modulu
		      TPM2B           *p,             // OUT: One of the prime factors of n
		      UINT16           keySizeInBits, // IN: Size of the public modulus in bit
		      UINT32           e,             // IN: The public exponent
		      TPM_ALG_ID       hashAlg,       // IN: hash algorithm to use in the key
		      //     generation proce
		      TPM2B           *seed,          // IN: the seed to use
		      const char      *label,         // IN: A label for the generation process.
		      TPM2B           *extra,         // IN: Party 1 data for the KDF
		      UINT32          *counter        // IN/OUT: Counter value to allow KFD iteration
		      //     to be propagated across multiple routine
		      );


#endif
