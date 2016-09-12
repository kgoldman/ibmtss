/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriSym_fp.h 55 2015-02-05 22:03:16Z kgoldman $		*/
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

#ifndef CPRISYM_FP_H
#define CPRISYM_FP_H

LIB_EXPORT BOOL
_cpri__SymStartup(
		  void
		  );
LIB_EXPORT INT16
_cpri__GetSymmetricBlockSize(
			     TPM_ALG_ID       symmetricAlg,  // IN: the symmetric algorithm
			     UINT16           keySizeInBits  // IN: the key size
			     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCBC(
		     BYTE            *dOut,          // OUT:
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size (is required to be a multiple
		     //     of 16 bytes)
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptCBC(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 byte
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCFB(
		     BYTE            *dOut,          // OUT: the encrypted
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptCFB(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCTR(
		     BYTE            *dOut,          // OUT: the encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );

#define _cpri__AESDecryptCTR(dOut, keySize, key, iv, dInSize, dIn)	\
    _cpri__AESEncryptCTR(						\
			 ((BYTE *)dOut),				\
			 ((UINT32)keySize),				\
			 ((BYTE *)key),					\
			 ((BYTE *)iv),					\
			 ((UINT32)dInSize),				\
			 ((BYTE *)dIn)					\
									)


LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptECB(
		     BYTE            *dOut,          // OUT: encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: clear text buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptECB(
		     BYTE            *dOut,          // OUT: the clear text data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: cipher text buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptOFB(
		     BYTE            *dOut,          // OUT: the encrypted/decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 byte
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );

#define _cpri__AESDecryptOFB(dOut,keySizeInBits, key, iv, dInSize, dIn) \
    _cpri__AESEncryptOFB (						\
			  ((BYTE *)dOut),				\
                              ((UINT32)keySizeInBits),			\
                              ((BYTE *)key),				\
                              ((BYTE *)iv),				\
                              ((UINT32)dInSize),			\
                              ((BYTE *)dIn)				\
			      )

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCBC(
		     BYTE            *dOut,          // OUT:
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size (is required to be a multiple
		     //     of 16 bytes)
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptCBC(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 byte
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCFB(
		     BYTE            *dOut,          // OUT: the encrypted
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7 / 8)
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptCFB(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCTR(
		     BYTE            *dOut,          // OUT: the encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptECB(
		     BYTE            *dOut,          // OUT: encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: clear text buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptECB(
		     BYTE            *dOut,          // OUT: the clear text data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: cipher text buffer
		     );
LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptOFB(
		     BYTE            *dOut,          // OUT: the encrypted/decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 byte
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     );
		     

#endif
