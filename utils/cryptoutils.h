/********************************************************************************/
/*										*/
/*			OpenSSL Crypto Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: cryptoutils.h 1257 2018-06-27 20:52:08Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2017.						*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#ifndef CRYPTUTILS_H
#define CRYPTUTILS_H

#include <openssl/pem.h>

#include <ibmtss/tss.h>

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC convertPemToEvpPrivKey(EVP_PKEY **evpPkey,
				  const char *pemKeyFilename,
				  const char *password);
    TPM_RC convertPemToEvpPubKey(EVP_PKEY **evpPkey,
				 const char *pemKeyFilename);
    TPM_RC convertEvpPubkeyToPem(EVP_PKEY *evpPubkey,
				 const char *pemFilename);
    TPM_RC verifySignatureFromPem(unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  const char *pemFilename);
    TPM_RC convertBin2Bn(BIGNUM **bn,
			 const unsigned char *bin,
			 unsigned int bytes);
    
    TPM_RC convertEvpPkeyToRsakey(RSA **rsaKey,
				  EVP_PKEY *evpPkey);
    TPM_RC convertRsaKeyToPrivateKeyBin(int 	*privateKeyBytes,
					uint8_t 	**privateKeyBin,
					const RSA	 *rsaKey);
    TPM_RC convertRsaKeyToPublicKeyBin(int 		*modulusBytes,
				       uint8_t 	**modulusBin,
				       const RSA 	*rsaKey);
    TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					    TPM2B_SENSITIVE *objectSensitive,
					    int 		privateKeyBytes,
					    uint8_t 	*privateKeyBin,
					    const char 	*password);
    TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					  int			keyType,
					  TPMI_ALG_SIG_SCHEME 	scheme,
					  TPMI_ALG_HASH 	nalg,
					  TPMI_ALG_HASH		halg,
					  int 			modulusBytes,
					  uint8_t 		*modulusBin);
    TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				  TPM2B_SENSITIVE 	*objectSensitive,
				  RSA 			*rsaKey,
				  const char 		*password);
    TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 RSA 			*rsaKey);
    TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				  TPM2B_PRIVATE 	*objectPrivate,
				  int			keyType,
				  TPMI_ALG_SIG_SCHEME 	scheme,
				  TPMI_ALG_HASH 	nalg,
				  TPMI_ALG_HASH		halg,
				  const char 		*pemKeyFilename,
				  const char 		*password);
    TPM_RC convertRsaDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				  TPM2B_SENSITIVE 	*objectSensitive,
				  int			keyType,
				  TPMI_ALG_SIG_SCHEME 	scheme,
				  TPMI_ALG_HASH 	nalg,
				  TPMI_ALG_HASH		halg,
				  const char		*derKeyFilename,
				  const char 		*password);
    TPM_RC convertRsaPemToPublic(TPM2B_PUBLIC 		*objectPublic,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char 		*pemKeyFilename);
    TPM_RC getRsaKeyParts(const BIGNUM **n,
			  const BIGNUM **e,
			  const BIGNUM **d,
			  const BIGNUM **p,
			  const BIGNUM **q,
			  const RSA *rsaKey);
    int getRsaPubkeyAlgorithm(EVP_PKEY *pkey);
    TPM_RC convertPublicToPEM(const TPM2B_PUBLIC *public,
			      const char *pemFilename);
    TPM_RC convertRsaPublicToEvpPubKey(EVP_PKEY **evpPubkey,
				       const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa);
    TPM_RC verifyRSASignatureFromEvpPubKey(unsigned char *message,
					   unsigned int messageSize,
					   TPMT_SIGNATURE *tSignature,
					   TPMI_ALG_HASH halg,
					   EVP_PKEY *evpPkey);
    TPM_RC verifyRSASignatureFromRSA(unsigned char *message,
				     unsigned int messageSize,
				     TPMT_SIGNATURE *tSignature,
				     TPMI_ALG_HASH halg,
				     RSA *rsaPubKey);
    TPM_RC convertRsaBinToTSignature(TPMT_SIGNATURE *tSignature,
				     TPMI_ALG_HASH halg,
				     uint8_t *signatureBin,
				     size_t signatureBinLen);

#ifndef TPM_TSS_NOECC
    TPM_RC convertEvpPkeyToEckey(EC_KEY **ecKey,
				 EVP_PKEY *evpPkey);
    TPM_RC convertEcKeyToPrivateKeyBin(int 		*privateKeyBytes,
				       uint8_t 	**privateKeyBin,
				       const EC_KEY *ecKey);
    TPM_RC convertEcKeyToPublicKeyBin(int 		*modulusBytes,
				      uint8_t 		**modulusBin,
				      const EC_KEY 	*ecKey);
    TPM_RC convertEcPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					 int			keyType,
					 TPMI_ALG_SIG_SCHEME 	scheme,
					 TPMI_ALG_HASH 		nalg,
					 TPMI_ALG_HASH		halg,
					 TPMI_ECC_CURVE 	curveID,
					 int 			modulusBytes,
					 uint8_t 		*modulusBin);
    TPM_RC convertEcPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					   TPM2B_SENSITIVE 	*objectSensitive,
					   int 			privateKeyBytes,
					   uint8_t 		*privateKeyBin,
					   const char 		*password);
    TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 		*objectPrivate,
				 TPM2B_SENSITIVE 	*objectSensitive,
				 EC_KEY 		*ecKey,
				 const char 		*password);
    TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
				int			keyType,
				TPMI_ALG_SIG_SCHEME 	scheme,
				TPMI_ALG_HASH 		nalg,
				TPMI_ALG_HASH		halg,
				EC_KEY 			*ecKey);
    TPM_RC convertEcPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				 TPM2B_PRIVATE 		*objectPrivate,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char 		*pemKeyFilename,
				 const char 		*password);
    TPM_RC convertEcPemToPublic(TPM2B_PUBLIC 		*objectPublic,
				int			keyType,
				TPMI_ALG_SIG_SCHEME 	scheme,
				TPMI_ALG_HASH 		nalg,
				TPMI_ALG_HASH		halg,
				const char		*pemKeyFilename);
    TPM_RC convertEcDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
				 TPM2B_SENSITIVE 	*objectSensitive,
				 int			keyType,
				 TPMI_ALG_SIG_SCHEME 	scheme,
				 TPMI_ALG_HASH 		nalg,
				 TPMI_ALG_HASH		halg,
				 const char		*derKeyFilename,
				 const char 		*password);
    TPM_RC convertEcPublicToEvpPubKey(EVP_PKEY **evpPubkey,	
				      const TPMS_ECC_POINT *tpmsEccPoint);
    TPM_RC verifyEcSignatureFromEvpPubKey(unsigned char *message,
					  unsigned int messageSize,
					  TPMT_SIGNATURE *tSignature,
					  EVP_PKEY *evpPkey);
    TPM_RC convertEcBinToTSignature(TPMT_SIGNATURE *tSignature,
				    TPMI_ALG_HASH halg,
				    const uint8_t *signatureBin,
				    size_t signatureBinLen);
    TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
		      const EC_KEY *ecKey);
    
 #endif	/* TPM_TSS_NOECC */

#ifdef __cplusplus
}
#endif

#endif
