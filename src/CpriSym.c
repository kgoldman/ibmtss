/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriSym.c 155 2015-03-19 20:18:22Z kgoldman $		*/
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

// B.11	CpriSym.c
// B.11.1.	Introduction

// This file contains the implementation of the symmetric block cipher modes allowed for a
// TPM. These function only use the single block encryption and decryption functions of OpesnSSL().

// Currently, this module only supports AES encryption. The SM4 code actually calls an AES routine
// B.11.2.	Includes, Defines, and Typedefs

#include    "OsslCryptoEngine.h"

// SM4 is not implemented in the version of OpenSSL() available to the author
#ifdef TPM_ALG_SM4
#error "SM4 is not available"
#endif

// B.11.3.	Utility Functions
// B.11.3.1.	_cpri_SymStartup()

LIB_EXPORT BOOL
_cpri__SymStartup(
		  void
		  )
{
    return TRUE;
}

// B.11.3.2.	_cpri__GetSymmetricBlockSize()
// This function returns the block size of the algorithm.
// Return Value	Meaning
// <= 0	cipher not supported
// > 0	the cipher block size in bytes

LIB_EXPORT INT16
_cpri__GetSymmetricBlockSize(
			     TPM_ALG_ID       symmetricAlg,  // IN: the symmetric algorithm
			     UINT16           keySizeInBits  // IN: the key size
			     )
{
    switch (symmetricAlg)
	{
#ifdef TPM_ALG_AES
	  case TPM_ALG_AES:
#endif
#ifdef TPM_ALG_SM4 // Both AES and SM4 use the same block size
	  case TPM_ALG_SM4:
#endif
	    if(keySizeInBits != 0)  // This is mostly to have a reference to
			            // keySizeInBits for the compiler
		return  16;
	    else
		return 0;
	    break;
	    
	  default:
	    return 0;
	}
}

// B.11.4.	AES Encryption
// B.11.4.1.	_cpri__AESEncryptCBC()
// This function performs AES encryption in CBC chain mode. The input dIn buffer is encrypted into dOut.

// The input iv buffer is required to have a size equal to the block size (16 bytes). The dInSize is
// required to be a multiple of the block size.

// Return Value	Meaning
// CRYPT_SUCCESS	if success
// CRYPT_PARAMETER	dInSize is not a multiple of the block size

LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCBC(
		     BYTE            *dOut,          // OUT:
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size (is required to be a multiple
		     //     of 16 bytes)
		     BYTE            *dIn            // IN: data buffer
		     )
{
    AES_KEY      AesKey;
    BYTE        *pIv;
    INT32        dSize;         // Need a signed version
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create AES encrypt key schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // XOR the data block into the IV, encrypt the IV into the IV
    // and then copy the IV to the output
    for(; dSize > 0; dSize -= 16)
	{
	    pIv = iv;
	    for(i = 16; i > 0; i--)
		*pIv++ ^= *dIn++;
	    AES_encrypt(iv, iv, &AesKey);
	    pIv = iv;
	    for(i = 16; i > 0; i--)
		*dOut++ = *pIv++;
	}
    return CRYPT_SUCCESS;
}

// B.11.4.2.	_cpri__AESDecryptCBC()
// This function performs AES decryption in CBC chain mode. The input dIn buffer is decrypted into dOut.

// The input iv buffer is required to have a size equal to the block size (16 bytes). The dInSize is
// required to be a multiple of the block size.

// Return Value	Meaning
// CRYPT_SUCCESS	if success
// CRYPT_PARAMETER	dInSize is not a multiple of the block size

LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptCBC(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 bytes
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    AES_KEY      AesKey;
    BYTE        *pIv;
    int          i;
    BYTE         tmp[16];
    BYTE        *pT = NULL;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create AES key schedule
    if (AES_set_decrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // Copy the input data to a temp buffer, decrypt the buffer into the output;
    // XOR in the IV, and copy the temp buffer to the IV and repeat.
    for(; dSize > 0; dSize -= 16)
	{
	    pT = tmp;
	    for(i = 16; i> 0; i--)
		*pT++ = *dIn++;
	    AES_decrypt(tmp, dOut, &AesKey);
	    pIv = iv;
	    pT = tmp;
	    for(i = 16; i> 0; i--)
		{
		    *dOut++ ^= *pIv;
		    *pIv++ = *pT++;
		}
	}
    return CRYPT_SUCCESS;
}

// B.11.4.3.	_cpri__AESEncryptCFB()

// This function performs AES encryption in CFB chain mode. The dOut buffer receives the values
// encrypted dIn. The input iv is assumed to be the size of an encryption block (16 bytes). The iv
// buffer will be modified to contain the last encrypted block.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCFB(
		     BYTE            *dOut,          // OUT: the encrypted
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv = NULL;
    AES_KEY      AesKey;
    INT32        dSize;         // Need a signed version of dInSize
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create AES encryption key schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // Encrypt the IV into the IV, XOR in the data, and copy to output
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the current value of the IV
	    AES_encrypt(iv, iv, &AesKey);
	    pIv = iv;
	    for(i = (int)(dSize < 16) ? dSize : 16; i > 0; i--)
		// XOR the data into the IV to create the cipher text
		// and put into the output
		*dOut++ = *pIv++ ^= *dIn++;
	}
    // If the inner loop (i loop) was smaller than 16, then dSize would have been
    // smaller than 16 and it is now negative. If it is negative, then it indicates
    // how many bytes are needed to pad out the IV for the next round.
    for(; dSize < 0; dSize++)
	*pIv++ = 0;
    return CRYPT_SUCCESS;
}

// B.11.4.4.	_cpri__AESDecryptCFB()
// This function performs AES decrypt in CFB chain mode. The dOut buffer receives the values decrypted from dIn.

// The input iv is assumed to be the size of an encryption block (16 bytes). The iv buffer will be
// modified to contain the last decoded block, padded with zeros

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptCFB(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv = NULL;
    BYTE         tmp[16];
    int          i;
    BYTE        *pT;
    AES_KEY      AesKey;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create AES encryption key schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the IV into the temp buffer
	    AES_encrypt(iv, tmp, &AesKey);
	    pT = tmp;
	    pIv = iv;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		// Copy the current cipher text to IV, XOR
		// with the temp buffer and put into the output
		*dOut++ = *pT++ ^ (*pIv++ = *dIn++);
	}
    // If the inner loop (i loop) was smaller than 16, then dSize
    // would have been smaller than 16 and it is now negative
    // If it is negative, then it indicates how may fill bytes
    // are needed to pad out the IV for the next round.
    for(; dSize < 0; dSize++)
	*pIv++ = 0;
    
    return CRYPT_SUCCESS;
}

// B.11.4.5.	_cpri__AESEncryptCTR()

// This function performs AES encryption/decryption in CTR chain mode. The dIn buffer is encrypted
// into dOut. The input iv buffer is assumed to have a size equal to the AES block size (16
// bytes). The iv will be incremented by the number of blocks (full and partial) that were
// encrypted.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptCTR(
		     BYTE            *dOut,          // OUT: the encrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE         tmp[16];
    BYTE        *pT;
    AES_KEY      AesKey;
    int          i;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create AES encryption schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the current value of the IV(counter)
	    AES_encrypt(iv, (BYTE *)tmp, &AesKey);
	    
	    //increment the counter (counter is big-endian so start at end)
	    for(i = 15; i >= 0; i--)
		if((iv[i] += 1) != 0)
		    break;
	    
	    // XOR the encrypted counter value with input and put into output
	    pT = tmp;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		*dOut++ = *dIn++ ^ *pT++;
	}
    return CRYPT_SUCCESS;
}

// B.11.4.6.	_cpri__AESDecryptCTR()

// Counter mode decryption uses the same algorithm as encryption. The _cpri__AESDecryptCTR()
// function is implemented as a macro call to _cpri__AESEncryptCTR(). (skip)

#if 0
 #define _cpri__AESDecryptCTR(dOut, keySize, key, iv, dInSize, dIn)	\
         _cpri__AESEncryptCTR(						\
                              ((BYTE *)dOut),				\
                              ((UINT32)keySize),			\
                              ((BYTE *)key),				\
                              ((BYTE *)iv),				\
                              ((UINT32)dInSize),			\
                              ((BYTE *)dIn)				\
                             )

#endif

// The //% is used by the prototype extraction program to cause it to include the line in the
// prototype file after removing the //%.  Need an extra line with nothing on it so that a blank
// line will separate this macro from the next definition.

// B.11.4.7.	_cpri__AESEncryptECB()
// AES encryption in ECB mode. The data buffer is modified to contain the cipher text.
// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptECB(
		     BYTE            *dOut,          // OUT: encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: clear text buffer
		     )
{
    AES_KEY      AesKey;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    // Create AES encrypting key schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    AES_encrypt(dIn, dOut, &AesKey);
	    dIn = &dIn[16];
	    dOut = &dOut[16];
	}
    return CRYPT_SUCCESS;
}

// B.11.4.8.	_cpri__AESDecryptECB()
// This function performs AES decryption using ECB (not recommended). The cipher text dIn is decrypted into dOut.
// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESDecryptECB(
		     BYTE            *dOut,          // OUT: the clear text data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: cipher text buffer
		     )
{
    AES_KEY      AesKey;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create AES decryption key schedule
    if (AES_set_decrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    AES_decrypt(dIn, dOut, &AesKey);
	    dIn = &dIn[16];
	    dOut = &dOut[16];
	}
    return CRYPT_SUCCESS;
}

// B.11.4.9.	_cpri__AESEncryptOFB()

// This function performs AES encryption/decryption in OFB chain mode. The dIn buffer is modified to
// contain the encrypted/decrypted text.

// The input iv buffer is assumed to have a size equal to the block size (16 bytes). The returned
// value of iv will be the nth encryption of the IV, where n is the number of blocks (full or
// partial) in the data stream.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__AESEncryptOFB(
		     BYTE            *dOut,          // OUT: the encrypted/decrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 byte
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv;
    AES_KEY      AesKey;
    INT32        dSize;
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create AES key schedule
    if (AES_set_encrypt_key(key, keySizeInBits, &AesKey) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // This is written so that dIn and dOut may be the same
    
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the current value of the "IV"
	    AES_encrypt(iv, iv, &AesKey);
	    
	    // XOR the encrypted IV into dIn to create the cipher text (dOut)
	    pIv = iv;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		*dOut++ = (*pIv++ ^ *dIn++);
	}
    return CRYPT_SUCCESS;
}

// B.11.4.10.	_cpri__AESDecryptOFB()

// OFB encryption and decryption use the same algorithms for both. The _cpri__AESDecryptOFB()
// function is implemented as a macro call to _cpri__AESEncrytOFB(). (skip)

#if 0
#define _cpri__AESDecryptOFB(dOut,keySizeInBits, key, iv, dInSize, dIn) \
        _cpri__AESEncryptOFB (						\
                              ((BYTE *)dOut),				\
                              ((UINT32)keySizeInBits),			\
                              ((BYTE *)key),				\
                              ((BYTE *)iv),				\
                              ((UINT32)dInSize),			\
                              ((BYTE *)dIn)				\
                             )

#endif
	    
#ifdef  TPM_ALG_SM4     //%

// B.11.5.	SM4 Encryption
// B.11.5.1.	_cpri__SM4EncryptCBC()
// This function performs SM4 encryption in CBC chain mode. The input dIn buffer is encrypted into dOut.

// The input iv buffer is required to have a size equal to the block size (16 bytes). The dInSize is
// required to be a multiple of the block size.

// Return Value	Meaning
// CRYPT_SUCCESS	if success
// CRYPT_PARAMETER	dInSize is not a multiple of the block size

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCBC(
		     BYTE            *dOut,          // OUT:
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size (is required to be a multiple
		     //     of 16 bytes)
		     BYTE            *dIn            // IN: data buffer
		     )
{
    SM4_KEY      Sm4Key;
    BYTE        *pIv;
    INT32        dSize;         // Need a signed version
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create SM4 encrypt key schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // XOR the data block into the IV, encrypt the IV into the IV
    // and then copy the IV to the output
    for(; dSize > 0; dSize -= 16)
	{
	    pIv = iv;
	    for(i = 16; i > 0; i--)
		*pIv++ ^= *dIn++;
	    SM4_encrypt(iv, iv, &Sm4Key);
	    pIv = iv;
	    for(i = 16; i > 0; i--)
		*dOut++ = *pIv++;
	}
    return CRYPT_SUCCESS;
}

// B.11.5.2.	_cpri__SM4DecryptCBC()
// This function performs SM4 decryption in CBC chain mode. The input dIn buffer is decrypted into dOut.

// The input iv buffer is required to have a size equal to the block size (16 bytes). The dInSize is
// required to be a multiple of the block size.

// Return Value	Meaning
// CRYPT_SUCCESS	if success
// CRYPT_PARAMETER	dInSize is not a multiple of the block size

LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptCBC(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 bytes
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    SM4_KEY      Sm4Key;
    BYTE        *pIv;
    int          i;
    BYTE         tmp[16];
    BYTE        *pT = NULL;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For CBC, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create SM4 key schedule
    if (SM4_set_decrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // Copy the input data to a temp buffer, decrypt the buffer into the output;
    // XOR in the IV, and copy the temp buffer to the IV and repeat.
    for(; dSize > 0; dSize -= 16)
	{
	    pT = tmp;
	    for(i = 16; i> 0; i--)
		*pT++ = *dIn++;
	    SM4_decrypt(tmp, dOut, &Sm4Key);
	    pIv = iv;
	    pT = tmp;
	    for(i = 16; i> 0; i--)
		{
		    *dOut++ ^= *pIv;
		    *pIv++ = *pT++;
		}
	}
    return CRYPT_SUCCESS;
}

// B.11.5.3.	_cpri__SM4EncryptCFB()

// This function performs SM4 encryption in CFB chain mode. The dOut buffer receives the values
// encrypted dIn. The input iv is assumed to be the size of an encryption block (16 bytes). The iv
// buffer will be modified to contain the last encrypted block.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCFB(
		     BYTE            *dOut,          // OUT: the encrypted
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv;
    SM4_KEY      Sm4Key;
    INT32        dSize;         // Need a signed version of dInSize
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create SM4 encryption key schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // Encrypt the IV into the IV, XOR in the data, and copy to output
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the current value of the IV
	    SM4_encrypt(iv, iv, &Sm4Key);
	    pIv = iv;
	    for(i = (int)(dSize < 16) ? dSize : 16; i > 0; i--)
		// XOR the data into the IV to create the cipher text
		// and put into the output
		*dOut++ = *pIv++ ^= *dIn++;
	}
    return CRYPT_SUCCESS;
}

// B.11.5.4.	_cpri__SM4DecryptCFB()
// This function performs SM4 decrypt in CFB chain mode. The dOut buffer receives the values decrypted from dIn.

// The input iv is assumed to be the size of an encryption block (16 bytes). The iv buffer will be
// modified to contain the last decoded block, padded with zeros

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptCFB(
		     BYTE            *dOut,          // OUT: the decrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv;
    BYTE         tmp[16];
    int          i;
    BYTE        *pT;
    SM4_KEY      Sm4Key;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create SM4 encryption key schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the IV into the temp buffer
	    SM4_encrypt(iv, tmp, &Sm4Key);
	    pT = tmp;
	    pIv = iv;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		// Copy the current cipher text to IV, XOR
		// with the temp buffer and put into the output
		*dOut++ = *pT++ ^ (*pIv++ = *dIn++);
	}
    // If the inner loop (i loop) was smaller than 16, then dSize
    // would have been smaller than 16 and it is now negative
    // If it is negative, then it indicates how may fill bytes
    // are needed to pad out the IV for the next round.
    for(; dSize < 0; dSize++)
	*iv++ = 0;
    
    return CRYPT_SUCCESS;
}

// B.11.5.5.	_cpri__SM4EncryptCTR()

// This function performs SM4 encryption/decryption in CTR chain mode. The dIn buffer is encrypted
// into dOut. The input iv buffer is assumed to have a size equal to the SM4 block size (16
// bytes). The iv will be incremented by the number of blocks (full and partial) that were
// encrypted.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptCTR(
		     BYTE            *dOut,          // OUT: the encrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption.
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE         tmp[16];
    BYTE        *pT;
    SM4_KEY      Sm4Key;
    int          i;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create SM4 encryption schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize--)
	{
	    // Encrypt the current value of the IV(counter)
	    SM4_encrypt(iv, (BYTE *)tmp, &Sm4Key);
	    
	    //increment the counter
	    for(i = 0; i < 16; i++)
		if((iv[i] += 1) != 0)
		    break;
	    
	    // XOR the encrypted counter value with input and put into output
	    pT = tmp;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		*dOut++ = *dIn++ ^ *pT++;
	}
    return CRYPT_SUCCESS;
}

// B.11.5.6.	_cpri__SM4DecryptCTR()

#if 0
// Counter mode decryption uses the same algorithm as encryption. The _cpri__SM4DecryptCTR()
// function is implemented as a macro call to _cpri__SM4EncryptCTR(). (skip)

 #define _cpri__SM4DecryptCTR(dOut, keySize, key, iv, dInSize, dIn)	\
         _cpri__SM4EncryptCTR(						\
                              ((BYTE *)dOut),				\
                              ((UINT32)keySize),			\
                              ((BYTE *)key),				\
                              ((BYTE *)iv),				\
                              ((UINT32)dInSize),			\
                              ((BYTE *)dIn)				\
                             )

#endif

// The //% is used by the prototype extraction program to cause it to include the line in the
// prototype file after removing the //%.  Need an extra line with nothing on it so that a blank
// line will separate this macro from the next definition.

// B.11.5.7.	_cpri__SM4EncryptECB()
// SM4 encryption in ECB mode. The data buffer is modified to contain the cipher text.
// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptECB(
		     BYTE            *dOut,          // OUT: encrypted data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: clear text buffer
		     )
{
    SM4_KEY      Sm4Key;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    // Create SM4 encrypting key schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    SM4_encrypt(dIn, dOut, &Sm4Key);
	    dIn = &dIn[16];
	    dOut = &dOut[16];
	}
    return CRYPT_SUCCESS;
}

// B.11.5.8.	_cpri__SM4DecryptECB()
// This function performs SM4 decryption using ECB (not recommended). The cipher text dIn is decrypted into dOut.
// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4DecryptECB(
		     BYTE            *dOut,          // OUT: the clear text data
		     UINT32           keySizeInBits, // IN: key size in bit
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: cipher text buffer
		     )
{
    SM4_KEY      Sm4Key;
    INT32        dSize;
    
    pAssert(dOut != NULL && key != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // For ECB, the data size must be an even multiple of the
    // cipher block size
    if((dSize % 16) != 0)
	return CRYPT_PARAMETER;
    
    // Create SM4 decryption key schedule
    if (SM4_set_decrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    for(; dSize > 0; dSize -= 16)
	{
	    SM4_decrypt(dIn, dOut, &Sm4Key);
	    dIn = &dIn[16];
	    dOut = &dOut[16];
	}
    return CRYPT_SUCCESS;
}

// B.11.5.9.	_cpri__SM4EncryptOFB()

// This function performs SM4 encryption/decryption in OFB chain mode. The dIn buffer is modified to
// contain the encrypted/decrypted text.

// The input iv buffer is assumed to have a size equal to the block size (16 bytes). The returned
// value of iv will be the nth encryption of the IV, where n is the number of blocks (full or
// partial) in the data stream.

// Return Value	Meaning
// CRYPT_SUCCESS	no non-fatal errors

LIB_EXPORT CRYPT_RESULT
_cpri__SM4EncryptOFB(
		     BYTE            *dOut,          // OUT: the encrypted/decrypted data
		     UINT32           keySizeInBits, // IN: key size in bits
		     BYTE            *key,           // IN: key buffer. The size of this buffer in
		     //     bytes is (keySizeInBits + 7) / 8
		     BYTE            *iv,            // IN/OUT: IV for decryption. The size of this
		     //     buffer is 16 bytes
		     UINT32           dInSize,       // IN: data size
		     BYTE            *dIn            // IN: data buffer
		     )
{
    BYTE        *pIv;
    SM4_KEY      Sm4Key;
    INT32        dSize;
    int          i;
    
    pAssert(dOut != NULL && key != NULL && iv != NULL && dIn != NULL);
    
    if(dInSize == 0)
	return CRYPT_SUCCESS;
    
    pAssert(dInSize <= INT32_MAX);
    dSize = (INT32)dInSize;
    
    // Create SM4 key schedule
    if (SM4_set_encrypt_key(key, keySizeInBits, &Sm4Key) != 0)
	FAIL(FATAL_ERROR_INTERNAL);
    
    // This is written so that dIn and dOut may be the same
    
    for(; dSize > 0; dSize -= 16)
	{
	    // Encrypt the current value of the "IV"
	    SM4_encrypt(iv, iv, &Sm4Key);
	    
	    // XOR the encrypted IV into dIn to create the cipher text (dOut)
	    pIv = iv;
	    for(i = (dSize < 16) ? dSize : 16; i > 0; i--)
		*dOut++ = (*pIv++ ^ *dIn++);
	}
    return CRYPT_SUCCESS;
}

// B.11.5.10.	_cpri__SM4DecryptOFB()
// OFB encryption and decryption use the same algorithms for both. The _cpri__SM4DecryptOFB() function is implemented as a macro call to _cpri__SM4EncrytOFB(). (skip)

#if 0
#define _cpri__SM4DecryptOFB(dOut,keySizeInBits, key, iv, dInSize, dIn) \
        _cpri__SM4EncryptOFB (					\
                              ((BYTE *)dOut),			\
                              ((UINT32)keySizeInBits),		\
                              ((BYTE *)key),				\
                              ((BYTE *)iv),				\
                              ((UINT32)dInSize),			\
                              ((BYTE *)dIn)				\
                             )

#endif
#endif      //% TPM_ALG_SM4
