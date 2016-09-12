/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CryptUtil_fp.h 471 2015-12-22 19:40:24Z kgoldman $		*/
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

#ifndef CRYPTUTIL_FP_H
#define CRYPTUTIL_FP_H

void
CryptDrbgGetPutState(
		     GET_PUT          direction      // IN: Get from or put to DRBG
		     );
void
CryptStirRandom(
		UINT32           entropySize,   // IN: size of entropy buffer
		BYTE            *buffer         // IN: entropy buffer
		);
UINT16
CryptGenerateRandom(
		    UINT16           randomSize,    // IN: size of random number
		    BYTE            *buffer         // OUT: buffer of random number
		    );
TPM_ALG_ID
CryptGetContextAlg(
		   void            *state          // IN: the context to check
		   );
UINT16
CryptStartHash(
	       TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
	       HASH_STATE      *hashState      // OUT: the state of hash stack. It will be used
	       //     in hash update and completion
	       );
UINT16
CryptStartHashSequence(
		       TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
		       HASH_STATE      *hashState      // OUT: the state of hash stack. It will be used
		       //     in hash update and completion
		       );
UINT16
CryptStartHMAC(
	       TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
	       UINT16           keySize,       // IN: the size of HMAC key in byte
	       BYTE            *key,           // IN: HMAC key
	       HMAC_STATE      *hmacState      // OUT: the state of HMAC stack. It will be used
	       //     in HMAC update and completion
	       );
UINT16
CryptStartHMACSequence(
		       TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
		       UINT16           keySize,       // IN: the size of HMAC key in byte
		       BYTE            *key,           // IN: HMAC key
		       HMAC_STATE      *hmacState      // OUT: the state of HMAC stack. It will be used
		       //     in HMAC update and completion
		       );
LIB_EXPORT UINT16
CryptStartHMAC2B(
		 TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
		 TPM2B           *key,           // IN: HMAC key
		 HMAC_STATE      *hmacState      // OUT: the state of HMAC stack. It will be used
		 //     in HMAC update and completion
		 );
UINT16
CryptStartHMACSequence2B(
			 TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
			 TPM2B           *key,           // IN: HMAC key
			 HMAC_STATE      *hmacState      // OUT: the state of HMAC stack. It will be used
			 //     in HMAC update and completion
			 );
LIB_EXPORT void
CryptUpdateDigest(
		  void            *digestState,   // IN: the state of hash stack
		  UINT32           dataSize,      // IN: the size of data
		  BYTE            *data           // IN: data to be hashed
		  );
LIB_EXPORT void
CryptUpdateDigest2B(
		    void            *digestState,   // IN: the digest state
		    TPM2B           *bIn            // IN: 2B containing the data
		    );
LIB_EXPORT void
CryptUpdateDigestInt(
		     void            *state,         // IN: the state of hash stack
		     UINT32           intSize,       // IN: the size of 'intValue' in byte
		     void            *intValue       // IN: integer value to be hashed
		     );
LIB_EXPORT UINT16
CryptCompleteHash(
		  void            *state,         // IN: the state of hash stack
		  UINT16           digestSize,    // IN: size of digest buffer
		  BYTE            *digest         // OUT: hash digest
		  );
LIB_EXPORT UINT16
CryptCompleteHash2B(
		    void            *state,         // IN: the state of hash stack
		    TPM2B           *digest         // IN: the size of the buffer Out: requested
		    //     number of byte
		    );
LIB_EXPORT UINT16
CryptHashBlock(
	       TPM_ALG_ID       algId,         // IN: the hash algorithm to use
	       UINT16           blockSize,     // IN: size of the data block
	       BYTE            *block,         // IN: address of the block to hash
	       UINT16           retSize,       // IN: size of the return buffer
	       BYTE            *ret            // OUT: address of the buffer
	       );
LIB_EXPORT UINT16
CryptCompleteHMAC(
		  HMAC_STATE      *hmacState,     // IN: the state of HMAC stack
		  UINT32           digestSize,    // IN: size of digest buffer
		  BYTE            *digest         // OUT: HMAC digest
		  );
LIB_EXPORT UINT16
CryptCompleteHMAC2B(
		    HMAC_STATE      *hmacState,     // IN: the state of HMAC stack
		    TPM2B           *digest         // OUT: HMAC
		    );
void
CryptHashStateImportExport(
			   HASH_STATE      	*internalFmt,   // IN: state to LIB_EXPORT
			   HASH_STATE_BUFFER    *externalFmt,   // OUT: exported state
			   IMPORT_EXPORT    	direction
			   );
LIB_EXPORT UINT16
CryptGetHashDigestSize(
		       TPM_ALG_ID       hashAlg        // IN: hash algorithm
		       );
LIB_EXPORT UINT16
CryptGetHashBlockSize(
		      TPM_ALG_ID       hash           // IN: hash algorithm to look up
		      );
LIB_EXPORT TPM_ALG_ID
CryptGetHashAlgByIndex(
		       UINT32           index          // IN: the index
		       );

#define CryptKDFa(hashAlg, key, label, contextU, contextV,	\
		sizeInBits, keyStream, counterInOut)		\
		TEST_HASH(hashAlg);				\
	_cpri__KDFa(						\
	    ((TPM_ALG_ID)hashAlg),				\
	    ((TPM2B *)key),					\
	    ((const char *)label),				\
	    ((TPM2B *)contextU),				\
	    ((TPM2B *)contextV),				\
	    ((UINT32)sizeInBits),				\
	    ((BYTE *)keyStream),				\
	    ((UINT32 *)counterInOut),				\
	    ((BOOL) FALSE)					\
	)

#define CryptKDFaOnce(hashAlg, key, label, contextU, contextV,	\
                      sizeInBits, keyStream, counterInOut)	\
         TEST_HASH(hashAlg);					\
        _cpri__KDFa(						\
                     ((TPM_ALG_ID)hashAlg),			\
                     ((TPM2B *)key),				\
                     ((const char *)label),			\
                     ((TPM2B *)contextU),			\
                     ((TPM2B *)contextV),			\
                     ((UINT32)sizeInBits),			\
                     ((BYTE *)keyStream),			\
                     ((UINT32 *)counterInOut),			\
                     ((BOOL) TRUE)				\
                    )


void
KDFa(
     TPM_ALG_ID       hash,          // IN: hash algorithm used in HMAC
     TPM2B           *key,           // IN: HMAC key
     const char      *label,         // IN: a null-terminated label for KDF
     TPM2B           *contextU,      // IN: context U
     TPM2B           *contextV,      // IN: context V
     UINT32           sizeInBits,    // IN: size of generated key in bit
     BYTE            *keyStream,     // OUT: key buffer
     UINT32          *counterInOut   // IN/OUT: caller may provide the iteration
     //     counter for incremental operations to
     //     avoid large intermediate buffers.
     );


#define CryptKDFe(hashAlg, Z, label, partyUInfo, partyVInfo,	\
                  sizeInBits, keyStream)			\
 TEST_HASH(hashAlg);						\
 _cpri__KDFe(							\
             ((TPM_ALG_ID)hashAlg),				\
             ((TPM2B *)Z),					\
             ((const char *)label),				\
             ((TPM2B *)partyUInfo),				\
             ((TPM2B *)partyVInfo),				\
             ((UINT32)sizeInBits),				\
             ((BYTE *)keyStream)				\
             )

TPM_RC
CryptTestKeyRSA(
		TPM2B           *d,             // OUT: receives the private exponent
		UINT32           e,             // IN: public exponent
		TPM2B           *n,             // IN/OUT: public modulu
		TPM2B           *p,             // IN: a first prime
		TPM2B           *q              // IN: an optional second prime
		);
TPM_RC
CryptLoadPrivateRSA(
		    OBJECT          *rsaKey         // IN: the RSA key object
		    );
TPMT_RSA_DECRYPT*
CryptSelectRSAScheme(
		     TPMI_DH_OBJECT       rsaHandle,     // IN: handle of sign key
		     TPMT_RSA_DECRYPT    *scheme         // IN: a sign or decrypt scheme
		     );
TPM_RC
CryptDecryptRSA(
		UINT16              *dataOutSize,   // OUT: size of plain text in byte
		BYTE                *dataOut,       // OUT: plain text
		OBJECT              *rsaKey,        // IN: internal RSA key
		TPMT_RSA_DECRYPT    *scheme,        // IN: selects the padding scheme
		UINT16               cipherInSize,  // IN: size of cipher text  in byte
		BYTE                *cipherIn,      // IN: cipher text
		const char          *label          // IN: a label, when needed
		);
TPM_RC
CryptEncryptRSA(
		UINT16              *cipherOutSize, // OUT: size of cipher text in byte
		BYTE                *cipherOut,     // OUT: cipher text
		OBJECT              *rsaKey,        // IN: internal RSA key
		TPMT_RSA_DECRYPT    *scheme,        // IN: selects the padding scheme
		UINT16               dataInSize,    // IN: size of plain text in byte
		BYTE                *dataIn,        // IN: plain text
		const char          *label          // IN: an optional label
		);
UINT16
CryptEccGetKeySizeInBits(
			 TPM_ECC_CURVE    curveID        // IN: id of the curve
			 );

#define CryptEccGetKeySizeInBytes(curve)			\
            ((CryptEccGetKeySizeInBits(curve)+7)/8)


LIB_EXPORT const TPM2B *
CryptEccGetParameter(
		     char             p,             // IN: the parameter selector
		     TPM_ECC_CURVE    curveId        // IN: the curve id
		     );
const TPMT_ECC_SCHEME *
CryptGetCurveSignScheme(
			TPM_ECC_CURVE    curveId        // IN: The curve selector
			);
BOOL
CryptEccIsPointOnCurve(
		       TPM_ECC_CURVE    curveID,       // IN: ECC curve ID
		       TPMS_ECC_POINT  *Q              // IN: ECC point
		       );
TPM_RC
CryptNewEccKey(
	       TPM_ECC_CURVE            curveID,       // IN: ECC curve
	       TPMS_ECC_POINT          *publicPoint,   // OUT: public point
	       TPM2B_ECC_PARAMETER     *sensitive      // OUT: private area
	       );
TPM_RC
CryptEccPointMultiply(
		      TPMS_ECC_POINT          *pOut,          // OUT: output point
		      TPM_ECC_CURVE            curveId,       // IN: curve selector
		      TPM2B_ECC_PARAMETER     *dIn,           // IN: public scalar
		      TPMS_ECC_POINT          *pIn            // IN: optional point
		      );
BOOL
CryptGenerateR(
	       TPM2B_ECC_PARAMETER     *r,             // OUT: the generated random value
	       UINT16                  *c,             // IN/OUT: count value.
	       TPMI_ECC_CURVE           curveID,       // IN: the curve for the value
	       TPM2B_NAME              *name           // IN: optional name of a key to
	       //     associate with 'r'
	       );
UINT16
CryptCommit(
	    void
	    );
void
CryptEndCommit(
	       UINT16           c              // IN: the counter value of the commitment
	       );
TPM_RC
CryptCommitCompute(
		   TPMS_ECC_POINT          *K,             // OUT: [d]B
		   TPMS_ECC_POINT          *L,             // OUT: [r]B
		   TPMS_ECC_POINT          *E,             // OUT: [r]M
		   TPM_ECC_CURVE            curveID,       // IN: The curve for the computation
		   TPMS_ECC_POINT          *M,             // IN: M (P1)
		   TPMS_ECC_POINT          *B,             // IN: B (x2, y2)
		   TPM2B_ECC_PARAMETER     *d,             // IN: the private scalar
		   TPM2B_ECC_PARAMETER     *r              // IN: the computed r value
		   );
BOOL
CryptEccGetParameters(
		      TPM_ECC_CURVE                curveId,       // IN: ECC curve ID
		      TPMS_ALGORITHM_DETAIL_ECC   *parameters     // OUT: ECC parameter
		      );
TPM_RC
CryptEcc2PhaseKeyExchange(
			  TPMS_ECC_POINT          *outZ1,         // OUT: the computed point
			  TPMS_ECC_POINT          *outZ2,         // OUT: optional second point
			  TPM_ALG_ID               scheme,        // IN: the key exchange scheme
			  TPM_ECC_CURVE            curveId,       // IN: the curve for the computation
			  TPM2B_ECC_PARAMETER     *dsA,           // IN: static private TPM key
			  TPM2B_ECC_PARAMETER     *deA,           // IN: ephemeral private TPM key
			  TPMS_ECC_POINT          *QsB,           // IN: static public party B key
			  TPMS_ECC_POINT          *QeB            // IN: ephemeral public party B key
			  );
BOOL
CryptIsSchemeAnonymous(
		       TPM_ALG_ID       scheme         // IN: the scheme algorithm to test
		       );
void
ParmDecryptSym(
	       TPM_ALG_ID       symAlg,        // IN: the symmetric algorithm
	       TPM_ALG_ID       hash,          // IN: hash algorithm for KDFa
	       UINT16           keySizeInBits, // IN: key key size in bit
	       TPM2B           *key,           // IN: KDF HMAC key
	       TPM2B           *nonceCaller,   // IN: nonce caller
	       TPM2B           *nonceTpm,      // IN: nonce TPM
	       UINT32           dataSize,      // IN: size of parameter buffer
	       BYTE            *data           // OUT: buffer to be decrypted
	       );
void
ParmEncryptSym(
	       TPM_ALG_ID       symAlg,        // IN: symmetric algorithm
	       TPM_ALG_ID       hash,          // IN: hash algorithm for KDFa
	       UINT16           keySizeInBits, // IN: AES key size in bit
	       TPM2B           *key,           // IN: KDF HMAC key
	       TPM2B           *nonceCaller,   // IN: nonce caller
	       TPM2B           *nonceTpm,      // IN: nonce TPM
	       UINT32           dataSize,      // IN: size of parameter buffer
	       BYTE            *data           // OUT: buffer to be encrypted
	       );
void
CryptGenerateNewSymmetric(
			  TPMS_SENSITIVE_CREATE   *sensitiveCreate,   // IN: sensitive creation data
			  TPMT_SENSITIVE          *sensitive,         // OUT: sensitive area
			  TPM_ALG_ID               hashAlg,           // IN: hash algorithm for the KDF
			  TPM2B_SEED              *seed,              // IN: seed used in creation
			  TPM2B_NAME              *name               // IN: name of the object
			  );
void
CryptXORObfuscation(
		    TPM_ALG_ID       hash,          // IN: hash algorithm for KDF
		    TPM2B           *key,           // IN: KDF key
		    TPM2B           *contextU,      // IN: contextU
		    TPM2B           *contextV,      // IN: contextV
		    UINT32           dataSize,      // IN: size of data buffer
		    BYTE            *data           // IN/OUT: data to be XORed in place
		    );
void
CryptInitUnits(
	       void
	       );
void
CryptStopUnits(
	       void
	       );
BOOL
CryptUtilStartup(
		 STARTUP_TYPE     type           // IN: the startup type
		 );
BOOL
CryptIsAsymAlgorithm(
		     TPM_ALG_ID       algID          // IN: algorithm ID
		     );
INT16
CryptGetSymmetricBlockSize(
			   TPMI_ALG_SYM     algorithm,     // IN: symmetric algorithm
			   UINT16           keySize        // IN: key size in bit
			   );
void
CryptSymmetricEncrypt(
		      BYTE                *encrypted,     // OUT: the encrypted data
		      TPM_ALG_ID           algorithm,     // IN: algorithm for encryption
		      UINT16               keySizeInBits, // IN: key size in bit
		      TPMI_ALG_SYM_MODE    mode,          // IN: symmetric encryption mode
		      BYTE                *key,           // IN: encryption key
		      TPM2B_IV            *ivIn,          // IN/OUT: Input IV and output chaining
		      //     value for the next block
		      UINT32               dataSize,      // IN: data size in byte
		      BYTE                *data           // IN/OUT: data buffer
		      );
void
CryptSymmetricDecrypt(
		      BYTE                *decrypted,
		      TPM_ALG_ID           algorithm,     // IN: algorithm for encryption
		      UINT16               keySizeInBits, // IN: key size in bit
		      TPMI_ALG_SYM_MODE    mode,          // IN: symmetric encryption mode
		      BYTE                *key,           // IN: encryption key
		      TPM2B_IV            *ivIn,          // IN/OUT: IV for next block
		      UINT32               dataSize,      // IN: data size in byte
		      BYTE                *data           // IN/OUT: data buffer
		      );
TPM_RC
CryptSecretEncrypt(
		   TPMI_DH_OBJECT           keyHandle,     // IN: encryption key handle
		   const char              *label,         // IN: a null-terminated string as L
		   TPM2B_DATA              *data,          // OUT: secret value
		   TPM2B_ENCRYPTED_SECRET  *secret         // OUT: secret structure
		   );
TPM_RC
CryptSecretDecrypt(
		   TPM_HANDLE               tpmKey,        // IN: decrypt key
		   TPM2B_NONCE             *nonceCaller,   // IN: nonceCaller.  It is needed for
		   //     symmetric decryption.  For
		   //     asymmetric decryption, this
		   //     parameter is NULL
		   const char              *label,         // IN: a null-terminated string as L
		   TPM2B_ENCRYPTED_SECRET  *secret,        // IN: input secret
		   TPM2B_DATA              *data           // OUT: decrypted secret value
		   );
void
CryptParameterEncryption(
			 TPM_HANDLE       handle,            // IN: encrypt session handle
			 TPM2B           *nonceCaller,       // IN: nonce caller
			 UINT16           leadingSizeInByte, // IN: the size of the leading size field in
			 //     byte
			 TPM2B_AUTH      *extraKey,          // IN: additional key material other than
			 //     session auth
			 BYTE            *buffer             // IN/OUT: parameter buffer to be encrypted
			 );
TPM_RC
CryptParameterDecryption(
			 TPM_HANDLE       handle,            // IN: encrypted session handle
			 TPM2B           *nonceCaller,       // IN: nonce caller
			 UINT32           bufferSize,        // IN: size of parameter buffer
			 UINT16           leadingSizeInByte, // IN: the size of the leading size field in
			 //     byte
			 TPM2B_AUTH      *extraKey,          // IN: the authValue
			 BYTE            *buffer             // IN/OUT: parameter buffer to be decrypted
			 );
void
CryptComputeSymmetricUnique(
			    TPMI_ALG_HASH    nameAlg,       // IN: object name algorithm
			    TPMT_SENSITIVE  *sensitive,     // IN: sensitive area
			    TPM2B_DIGEST    *unique         // OUT: unique buffer
			    );
void
CryptComputeSymValue(
		     TPM_HANDLE       parentHandle,  // IN: parent handle of the object to be created
		     TPMT_PUBLIC     *publicArea,    // IN/OUT: the public area template
		     TPMT_SENSITIVE  *sensitive,     // IN: sensitive area
		     TPM2B_SEED      *seed,          // IN: the seed
		     TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm for KDFa
		     TPM2B_NAME      *name           // IN: object name
		     );
TPM_RC
CryptCreateObject(
		  TPM_HANDLE               parentHandle,      // IN/OUT: indication of the seed
		  //     source
		  TPMT_PUBLIC             *publicArea,        // IN/OUT: public area
		  TPMS_SENSITIVE_CREATE   *sensitiveCreate,   // IN: sensitive creation
		  TPMT_SENSITIVE          *sensitive          // OUT: sensitive area
		  );
BOOL
CryptObjectIsPublicConsistent(
			      TPMT_PUBLIC     *publicArea     // IN: public area
			      );
TPM_RC
CryptObjectPublicPrivateMatch(
			      OBJECT          *object         // IN: the object to check
			      );
TPMI_ALG_HASH
CryptGetSignHashAlg(
		    TPMT_SIGNATURE  *auth           // IN: signature
		    );
BOOL
CryptIsSplitSign(
		 TPM_ALG_ID       scheme         // IN: the algorithm selector
		 );
BOOL
CryptIsSignScheme(
		  TPMI_ALG_ASYM_SCHEME     scheme
		  );
BOOL
CryptIsDecryptScheme(
		     TPMI_ALG_ASYM_SCHEME     scheme
		     );
TPM_RC
CryptSelectSignScheme(
		      TPMI_DH_OBJECT       signHandle,    // IN: handle of signing key
		      TPMT_SIG_SCHEME     *scheme         // IN/OUT: signing scheme
		      );
TPM_RC
CryptSign(
	  TPMI_DH_OBJECT       signHandle,    // IN: The handle of sign key
	  TPMT_SIG_SCHEME     *signScheme,    // IN: sign scheme.
	  TPM2B_DIGEST        *digest,        // IN: The digest being signed
	  TPMT_SIGNATURE      *signature      // OUT: signature
	  );
TPM_RC
CryptVerifySignature(
		     TPMI_DH_OBJECT   keyHandle,     // IN: The handle of sign key
		     TPM2B_DIGEST    *digest,        // IN: The digest being validated
		     TPMT_SIGNATURE  *signature      // IN: signature
		     );
TPM_RC
CryptDivide(
	    TPM2B           *numerator,     // IN: numerator
	    TPM2B           *denominator,   // IN: denominator
	    TPM2B           *quotient,      // OUT: quotient = numerator / denominator.
	    TPM2B           *remainder      // OUT: numerator mod denominator.
	    );
LIB_EXPORT int
CryptCompare(
	     const UINT32     aSize,         // IN: size of a
	     const BYTE      *a,             // IN: a buffer
	     const UINT32     bSize,         // IN: size of b
	     const BYTE      *b              // IN: b buffer
	     );
int
CryptCompareSigned(
		   UINT32           aSize,         // IN: size of a
		   BYTE            *a,             // IN: a buffer
		   UINT32           bSize,         // IN: size of b
		   BYTE            *b              // IN: b buffer
		   );
TPM_RC
CryptGetTestResult(
		   TPM2B_MAX_BUFFER    *outData        // OUT: test result data
		   );
TPMI_YES_NO
CryptCapGetECCCurve(
		    TPM_ECC_CURVE    curveID,       // IN: the starting ECC curve
		    UINT32           maxCount,      // IN: count of returned curve
		    TPML_ECC_CURVE  *curveList      // OUT: ECC curve list
		    );
UINT32
CryptCapGetEccCurveNumber(
			  void
			  );
BOOL
CryptAreKeySizesConsistent(
			   TPMT_PUBLIC     *publicArea     // IN: the public area to check
			   );
void
CryptAlgsSetImplemented(
			void
			);


#endif
