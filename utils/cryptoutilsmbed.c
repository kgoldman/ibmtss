/********************************************************************************/
/*										*/
/*			MbedTLS Crypto Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2025.						*/
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

/* These functions are worthwhile sample code that probably (judgment call) do not belong in the TSS
   library.

   They show how to convert public or private EC or RSA among PEM format <-> mbedtls format <->
   binary arrays <-> TPM format TPM2B_PRIVATE, TPM2B_SENSITIVE, TPM2B_PUBLIC usable for loadexternal
   or import.

   There are functions to convert public keys from TPM <-> RSA, ECC <-> PEM, and to verify a TPM
   signature using a PEM format public key.

   This file variation uses the mbedtls crypto library.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include <mbedtls/pk.h>
#include <mbedtls/asn1.h>
#include <mbedtls/error.h>
#include <mbedtls/ctr_drbg.h>

#ifndef TPM_TSS_NOFILE
#include <ibmtss/tssfile.h>
#endif
#include <ibmtss/tssutils.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/Implementation.h>

#include "objecttemplates.h"
#include "cryptoutils.h"

int tssUtilsVerbose;

/* local function prototypes */

static TPM_RC pkContextNew(mbedtls_pk_context **ctx);
static void   pkContextFree(mbedtls_pk_context *ctx);
static TPM_RC convertPemToPk(mbedtls_pk_context **pkCtx,
			     const char *pemKeyFilename,
			     const char *password,
			     int public);
static TPM_RC getEcCurve(TPMI_ECC_CURVE 	*curveID,
			 int 			*privateKeyBytes,
			 mbedtls_ecp_group 	*grp);
static TPM_RC getEcGroupID(mbedtls_ecp_group_id *id,
			   TPMI_ECC_CURVE 	curveID);
static TPM_RC convertTpmHalgToMd(mbedtls_md_type_t 	*mdAlg,
				 TPMI_ALG_HASH 		halg);

#ifndef TPM_TSS_NORSA
static TPM_RC convertRsaPublicToMbedPubKey(mbedtls_pk_context **mbedPubkey,
					   const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa);
static TPM_RC convertRsaKeyToPrivateKeyBin(int 		*privateKeyBytes,
					   uint8_t 	**privateKeyBin,
					   mbedtls_rsa_context *rsaCtx);
static TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				     TPM2B_SENSITIVE 	*objectSensitive,
				     mbedtls_rsa_context *rsaCtx,
				     const char 	*password);
static TPM_RC getRsaKeyParts(mbedtls_mpi *n,
			     mbedtls_mpi *e,
			     mbedtls_mpi *d,
			     mbedtls_mpi *p,
			     mbedtls_mpi *q,
			     const mbedtls_rsa_context *rsaCtx);

static TPM_RC verifyRSASignatureFromPk(unsigned char *message,
				       unsigned int messageSize,
				       TPMT_SIGNATURE *tSignature,
				       TPMI_ALG_HASH halg,
				       mbedtls_pk_context *pkCtx);

#endif	/* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

static TPM_RC convertEcPublicToMbedPubKey(mbedtls_pk_context **mbedPubkey,
					  const TPMT_PUBLIC *tpmtPublic);
static TPM_RC convertEcKeyToPrivateKeyBin(int 			*privateKeyBytes,
					  uint8_t 		**privateKeyBin,
					  mbedtls_ecp_keypair 	*ecKp);
static TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 	*objectPublic,
				   int			keyType,
				   TPMI_ALG_SIG_SCHEME 	scheme,
				   TPMI_ALG_HASH 	nalg,
				   TPMI_ALG_HASH	halg,
				   mbedtls_ecp_keypair 	*ecKp);
static TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 		*objectPrivate,
				    TPM2B_SENSITIVE 		*objectSensitive,
				    mbedtls_ecp_keypair 	*ecKp,
				    const char 			*password);
static TPM_RC convertEcPublicKeyXYBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					      int			keyType,
					      TPMI_ALG_SIG_SCHEME 	scheme,
					      TPMI_ALG_HASH 		nalg,
					      TPMI_ALG_HASH		halg,
					      TPMI_ECC_CURVE 		curveID,
					      size_t 			xBytes,
					      uint8_t 			*xBin,
					      size_t 			yBytes,
					      uint8_t 			*yBin);
static TPM_RC verifyEcSignatureFromPk(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      mbedtls_pk_context *pkCtx);
static TPM_RC verifyEcSignatureFromEc(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      mbedtls_ecp_keypair *ecPubKey);

#endif	/* TPM_TSS_NOECC */

/* getCryptoLibrary() returns a string indicating the underlying crypto library.

   It can be used for programs and scripts that must account for library differences.
*/

void getCryptoLibrary(const char **name)
{
    *name = "mbedtls";
    return;
}

/* mbedtlsError() maps from the negative integer value to the hex values that are in the
   documentation.
*/

static void mbedtlsError(int irc)
{
    char buffer[512];
    int src = 0 - irc;
    mbedtls_strerror(irc, buffer, sizeof(buffer));
    printf("mbedtlsError -%04x %s\n", src, buffer);
    return;
}

/* pkContextNew() allocates allocates and initializes an mbedtls_pk_context public key token.

 */

static TPM_RC pkContextNew(mbedtls_pk_context **ctx)	/* freed by caller */
{
    TPM_RC 	rc = 0;

    /* sanity check for the free */
    if (rc == 0) {
	if (*ctx != NULL) {
	    printf("pkContextNew: Error (fatal), token %p should be NULL\n", *ctx);
            rc = TSS_RC_ALLOC_INPUT;
	}
    }
    /* allocate the mbedtls_pk_context */
    if (rc == 0) {
	rc = TSS_Malloc((unsigned char **)ctx, sizeof(mbedtls_pk_context));
    }
    /* initialize but do not set up the context */
    if (rc == 0) {
	mbedtls_pk_init(*ctx);
    }
    return rc;
}

/* pkContextFree() frees an mbedtls_pk_context public key token.

*/

static void pkContextFree(mbedtls_pk_context *ctx)
{
    mbedtls_pk_free(ctx);
    free(ctx);
}

/* convertPkToRsaKey() verifies that the mbedtls_pk_context encapsulates an RSA key
   and returns the inner structure
*/

TPM_RC convertPkToRsaKey(mbedtls_rsa_context **rsaCtx,
			 mbedtls_pk_context *pkCtx)
{
    TPM_RC 		rc = 0;
    mbedtls_pk_type_t 	pkType;

    /* validate that it is an RSA key */
    if (rc == 0) {
	pkType = mbedtls_pk_get_type(pkCtx);
	if (pkType != MBEDTLS_PK_RSA) {
	    printf("convertPkToRsaKey: key is not RSA\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* quick access the encapsulated mbedtls_rsa_context */
    if (rc == 0) {
	if (rsaCtx != NULL) {
	    *rsaCtx = mbedtls_pk_rsa(*pkCtx);
	}
    }
    return rc;
}

/* convertPkToEckey() verifies that the mbedtls_pk_context encapsulates an EC key
   and returns the inner structure
*/

TPM_RC convertPkToEckey(mbedtls_ecp_keypair **ecCtx,
			mbedtls_pk_context *pkCtx)
{
    TPM_RC 		rc = 0;
    mbedtls_pk_type_t 	pkType;

    /* validate that it is an EC key */
    if (rc == 0) {
	pkType = mbedtls_pk_get_type(pkCtx);
	if (pkType != MBEDTLS_PK_ECKEY) {
	    printf("convertPkToEckey: key is not EC\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* quick access the encapsulated mbedtls_ecp_keypair */
    if (rc == 0) {
	if (ecCtx != NULL) {
	    *ecCtx = mbedtls_pk_ec(*pkCtx);
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOFILE

/* convertPemToPk() converts a PEM format keypair or public key file to mbedtls_pk_context.

   The mbedtls_pk_context encapsulates either an RSA or ECC key.

   'public' is true for a keypair, false for a public key,
*/

static TPM_RC convertPemToPk(mbedtls_pk_context **pkCtx,		/* freed by caller */
			     const char *pemKeyFilename,
			     const char *password,
			     int public)
{
    TPM_RC 	rc = 0;
    int		irc;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* allocate and initialize the key context */
    if (rc == 0) {
	rc = pkContextNew(pkCtx);		/* freed by caller */
    }
    if (rc == 0) {
	/* read and map the private key */
	if (!public) {
	    mbedtls_ctr_drbg_init(&ctr_drbg);
	    irc = mbedtls_pk_parse_keyfile(*pkCtx,
					   pemKeyFilename,	/* PEM file path */
					   password,
					   mbedtls_ctr_drbg_random, &ctr_drbg);
	}
	/* read and map the public key */
	else {
	    irc = mbedtls_pk_parse_public_keyfile(*pkCtx,
						  pemKeyFilename);	/* PEM file path */
	}
	if (irc != 0) {
	    printf("convertPemToPk: Error parsing file %s public %d\n",
		   pemKeyFilename, public);
	    mbedtlsError(irc);
	    rc = TSS_RC_PEM_ERROR;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOECC

/* getEcCurve() gets the TCG TPMI_ECC_CURVE curveID curve and the size of the private key associated
   with the mbedtls_ecp_group

 */

static TPM_RC getEcCurve(TPMI_ECC_CURVE 	*curveID,
			 int 			*privateKeyBytes,
			 mbedtls_ecp_group 	*grp)
{
    TPM_RC 			rc = 0;
    mbedtls_ecp_group_id	id;

    if (rc == 0) {
	id = grp->id;
	/* mbedtls_ecp_group_id	to TCG curve ID */
	switch (id) {
	  case MBEDTLS_ECP_DP_SECP192R1:	/* untested guess */
	    *curveID = TPM_ECC_NIST_P192;
	    *privateKeyBytes = 24;
	    break;
	  case MBEDTLS_ECP_DP_SECP224R1:	/* untested guess */
	    *curveID = TPM_ECC_NIST_P224;
	    *privateKeyBytes = 28;
	    break;
	  case MBEDTLS_ECP_DP_SECP256R1:	/* TCG standard */
	    *curveID = TPM_ECC_NIST_P256;
	    *privateKeyBytes = 32;
	    break;
	  case MBEDTLS_ECP_DP_SECP384R1:	/* TCG standard */
	    *curveID = TPM_ECC_NIST_P384;
	    *privateKeyBytes = 48;
	    break;
	  case MBEDTLS_ECP_DP_BP256R1:		/* untested guess */
	    *curveID = TPM_ECC_BP_P256_R1;
	    *privateKeyBytes = 32;
	    break;
	  case MBEDTLS_ECP_DP_BP384R1:		/* untested guess */
	    *curveID = TPM_ECC_BP_P384_R1;
	    *privateKeyBytes = 48;
	    break;
	  case MBEDTLS_ECP_DP_BP512R1:		/* untested guess */
	    *curveID = TPM_ECC_BP_P512_R1;
	    *privateKeyBytes = 64;
	    break;
	  case MBEDTLS_ECP_DP_CURVE25519:	/* DTLS_ECP_DP_CURVE25519 */
	  case MBEDTLS_ECP_DP_SECP521R1:	/* DTLS_ECP_DP_SECP521R1 */
	  default:
	    printf("getEcCurve: Error, curve id %u not supported\n", id);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}

/* getEcGroupID() gets the mbedtls_ecp_group_id associated with the TCG TPMI_ECC_CURVE */

static TPM_RC getEcGroupID(mbedtls_ecp_group_id *id,
			   TPMI_ECC_CURVE 	curveID)
{
    TPM_RC 			rc = 0;

    switch (curveID) {
      case TPM_ECC_NIST_P192:
	*id = MBEDTLS_ECP_DP_SECP192R1;		/* untested guess */
	break;
      case TPM_ECC_NIST_P224:
	*id = MBEDTLS_ECP_DP_SECP224R1;		/* untested guess */
	break;
      case TPM_ECC_NIST_P256:
	*id = MBEDTLS_ECP_DP_SECP256R1;		/* TCG standard */
	break;
      case TPM_ECC_NIST_P384:
	*id = MBEDTLS_ECP_DP_SECP384R1;		/* TCG standard */
	break;
      case TPM_ECC_NIST_P521:
	*id = MBEDTLS_ECP_DP_SECP521R1;		/* untested guess */
	break;
      case TPM_ECC_BP_P256_R1:
	*id = MBEDTLS_ECP_DP_BP256R1;		/* untested guess */
	break;
      case TPM_ECC_BP_P384_R1:
	*id = MBEDTLS_ECP_DP_BP384R1;		/* untested guess */
	break;
      case TPM_ECC_BP_P512_R1:
	*id = MBEDTLS_ECP_DP_BP512R1;		/* untested guess */
	break;
      case TPM_ECC_CURVE_25519:
	*id = MBEDTLS_ECP_DP_CURVE25519;	/* untested guess */
	break;
      case TPM_ECC_BN_P256:
      case TPM_ECC_BN_P638:
      case TPM_ECC_SM2_P256:
      default:
	*id = MBEDTLS_ECP_DP_NONE;
	printf("getEcNid: Error, TCG curve %04x not supported \n", curveID);
	rc = TSS_RC_EC_KEY_CONVERT;
    }
    return rc;
}

#endif /* TPM_TSS_NOECC */

/* convertTpmHalgToMd() maps the TCG digest algorithm ID to the mbedtls message digest type */

static TPM_RC convertTpmHalgToMd(mbedtls_md_type_t 	*mdAlg,
				 TPMI_ALG_HASH 		hashAlg)
{
    TPM_RC 		rc = 0;

    if (rc == 0) {
	switch (hashAlg) {
	  case TPM_ALG_SHA1:
	    *mdAlg = MBEDTLS_MD_SHA1;
	    break;
	  case TPM_ALG_SHA256:
	    *mdAlg = MBEDTLS_MD_SHA256;
	    break;
	  case TPM_ALG_SHA384:
	    *mdAlg = MBEDTLS_MD_SHA384;
	    break;
	  case TPM_ALG_SHA512:
	    *mdAlg = MBEDTLS_MD_SHA512;
	    break;
	  default:
	    *mdAlg = MBEDTLS_MD_NONE;
	    printf("convertTpmHalgToMd: Error, hash algorithm %04hx unsupported\n", hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOFILE
#ifndef TPM_TSS_NORSA

/* convertPemToRsaPrivKey() converts a PEM format keypair file to a library specific RSA key
   token.  It validates that the algorithm is RSA.

   The return is void because the structure is opaque to the caller.  This accommodates other crypto
   libraries.

   rsaKey is an mbedtls_pk_context structure
*/

TPM_RC convertPemToRsaPrivKey(void **rsaKey,		/* freed by caller using TSS_RsaFree */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;

    /* convert a PEM file to an mbedtls_pk_context key pair */
    if (rc == 0) {
	rc = convertPemToPk((mbedtls_pk_context **)rsaKey,	/* freed by caller */
			    pemKeyFilename,
			    password,
			    FALSE);				/* key pair */
    }
    /* validate that it is an RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(NULL, *rsaKey);
    }
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif	/* TPM_TSS_NOFILE */

/* convertRsaKeyToPrivateKeyBin() converts an mbedtls_rsa_context RSA key token private prime p to a
   binary array

*/

#ifndef TPM_TSS_NORSA

static TPM_RC convertRsaKeyToPrivateKeyBin(int 		*privateKeyBytes,
					   uint8_t 	**privateKeyBin,	/* freed by caller */
					   mbedtls_rsa_context *rsaCtx)
{
    TPM_RC 		rc = 0;
    int 		irc;
    mbedtls_mpi 	p;	/* the RSA prime, private key */

    /* get the private primes */
    if (rc == 0) {
	rc = getRsaKeyParts(NULL, NULL, NULL, &p, NULL, rsaCtx);	/* freed @1 */
    }
    /* allocate a buffer for the private key array */
    if (rc == 0) {
	*privateKeyBytes = mbedtls_mpi_size(&p);
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key mbedtls_mpi binary */
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary(&p, *privateKeyBin, *privateKeyBytes);
	if (irc != 0) {
	    printf("convertRsaKeyToPrivateKeyBin: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_PrintAll("convertRsaKeyToPrivateKeyBin:", *privateKeyBin, *privateKeyBytes);
    }
    mbedtls_mpi_free(&p);	/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivateKeyBin() converts an mbedtls_ecp_keypair private key 'd' to a binary
   array */

static TPM_RC convertEcKeyToPrivateKeyBin(int 		*privateKeyBytes,
					  uint8_t	**privateKeyBin,  /* freed by caller */
					  mbedtls_ecp_keypair 	*ecKp)
{
    TPM_RC 			rc = 0;
    int				irc;
    mbedtls_ecp_group 		*grp;
    mbedtls_mpi 		*d;	/* ECC private key */
    int 			bnBytes;

    /* map group ID to size of private key */
    if (rc == 0) {
	TPMI_ECC_CURVE 	curveID;	/* TCG curveID not used */
	grp = &(ecKp->private_grp);
	rc = getEcCurve(&curveID, privateKeyBytes, grp);
    }
    /* get the ECC private key from the mbedtls_ecp_keypair as a mbedtls_mpi */
    if (rc == 0) {
	d = &(ecKp->private_d);
    }
    /* sanity check the mbedtls_mpi size against the curve */
    if (rc == 0) {
	bnBytes = mbedtls_mpi_size(d);
	if (bnBytes > *privateKeyBytes) {
	    printf("convertEcKeyToPrivateKeyBin: Error, private key %d bytes too large for curve\n",
		   bnBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* allocate a buffer for the private key array */
    if (rc == 0) {
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key mbedtls_mpi to binary */
    if (rc == 0) {
	/* TPM rev 116 required the ECC private key to be zero padded in the duplicate parameter of
	   import */
	memset(*privateKeyBin, 0, *privateKeyBytes - bnBytes);
	irc = mbedtls_mpi_write_binary(d,						/* input */
				       (*privateKeyBin) + (*privateKeyBytes - bnBytes),	/* buffer */
				       bnBytes);					/* size */
	if (irc != 0) {
	    printf("convertEcKeyToPrivateKeyBin: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPrivateKeyBin:", *privateKeyBin, *privateKeyBytes);
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublicKeyXYBin() converts an mbedtls_ecp_keypair token public points 'x' and 'y' to
   a binary arrays X and Y

*/

TPM_RC convertEcKeyToPublicKeyXYBin(size_t		*xBytes,
				    uint8_t 		**xBin,	/* freed by caller */
				    size_t		*yBytes,
				    uint8_t 		**yBin,	/* freed by caller */
				    mbedtls_ecp_keypair *ecKp)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_ecp_point 	*Q;
    mbedtls_mpi		*X;
    mbedtls_mpi		*Y;

    /* extract the X and Y public points */
    if (rc == 0) {
	Q = &(ecKp->private_Q);
	X = &(Q->private_X);
	Y = &(Q->private_Y);
	*xBytes = mbedtls_mpi_size(X);
	*yBytes = mbedtls_mpi_size(Y);
    }
    /* allocate the binary arrays */
    if (rc == 0) {
	rc = TSS_Malloc(xBin, *xBytes);	/* freed by caller */
    }
    if (rc == 0) {
	rc = TSS_Malloc(yBin, *yBytes);	/* freed by caller */
    }
    /* convert from mbedtls_mpi to array */
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary(X, *xBin, *xBytes);
	if (irc != 0) {
	    printf("convertEcKeyToPublicKeyXYBin: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary(Y, *yBin, *yBytes);
	if (irc != 0) {
	    printf("convertEcKeyToPublicKeyXYBin: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPublicKeyXYBin:", *xBin, *xBytes);
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPublicKeyXYBin:", *yBin, *yBytes);
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaKeyToPublicKeyBin() converts from an mbedtls RSA key token to a public
   modulus.

   The parameter is void because the structure is opaque to the caller.  This accommodates other
   crypto libraries.

   rsaKey is an mbedtls_rsa_context.
*/

#ifndef TPM_TSS_NORSA

TPM_RC convertRsaKeyToPublicKeyBin(int 		*modulusBytes,
				   uint8_t	**modulusBin,	/* freed by caller */
				   void 	*rsaKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_mpi 	n;

    /* get the public modulus n from the RSA key token */
    if (rc == 0) {
	rc = getRsaKeyParts(&n, NULL, NULL, NULL, NULL, rsaKey);	/* freed @1 */
    }
    /* allocate the binary array */
    if (rc == 0) {
	*modulusBytes = mbedtls_mpi_size(&n);
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    /* convert the public modulus mbedtls_mpi to binary */
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary(&n, *modulusBin, *modulusBytes);
	if (irc != 0) {
	    printf("convertRsaKeyToPublicKeyBin: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    mbedtls_mpi_free(&n);	/* @1 */
    return rc;
}

#endif /* TPM_TSS_NORSA */


#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPrivateKeyBinToPrivate() converts an EC 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE TPM structure.

*/

TPM_RC convertEcPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				       TPM2B_SENSITIVE 	*objectSensitive,
				       int 		privateKeyBytes,
				       uint8_t 		*privateKeyBin,
				       const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertEcPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_ECC;
	tSensitive.seedValue.b.size = 0;
	/* key password converted to TPM2B */
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.ecc.t.buffer)) {
	    printf("convertEcPrivateKeyBinToPrivate: Error, private key size %u not 32\n",
		   privateKeyBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.ecc.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.ecc.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif 	/* TPM_TSS_NOECC */
#endif 	/* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaPrivateKeyBinToPrivate() converts an RSA prime 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE

*/

TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					TPM2B_SENSITIVE *objectSensitive,
					int 		privateKeyBytes,
					uint8_t 	*privateKeyBin,
					const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertRsaPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_RSA;
	/* generate a seed for storage keys */
	tSensitive.seedValue.b.size = 32; 	/* FIXME hard coded seed length */
	rc = TSS_RandBytes(tSensitive.seedValue.b.buffer, tSensitive.seedValue.b.size);
    }
    /* key password converted to TPM2B */
    if (rc == 0) {
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.rsa.t.buffer)) {
	    printf("convertRsaPrivateKeyBinToPrivate: "
		   "Error, private key modulus %d greater than %lu\n",
		   privateKeyBytes, (unsigned long)sizeof(tSensitive.sensitive.rsa.t.buffer));
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.rsa.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.rsa.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif /* TPM_TPM20 */

/* convertEcPublicKeyXYBinToPublic() converts EC X and Y public points and other parameters to a
   TPM2B_PUBLIC

   NOTE:  This version accepts X and Y points.
*/

#ifndef TPM_TSS_NOECC

static TPM_RC convertEcPublicKeyXYBinToPublic(TPM2B_PUBLIC 		*objectPublic,
					      int			keyType,
					      TPMI_ALG_SIG_SCHEME 	scheme,
					      TPMI_ALG_HASH 		nalg,
					      TPMI_ALG_HASH		halg,
					      TPMI_ECC_CURVE 		curveID,
					      size_t 			xBytes,
					      uint8_t 			*xBin,
					      size_t 			yBytes,
					      uint8_t 			*yBin)
{
    TPM_RC 		rc = 0;

    scheme = scheme;	/* scheme parameter not supported yet */
    if (rc == 0) {
	if ((xBytes > sizeof(objectPublic->publicArea.unique.ecc.x.t.buffer)) ||
	    (yBytes > sizeof(objectPublic->publicArea.unique.ecc.y.t.buffer))) {
	    printf("convertEcPublicKeyXYBinToPublic: x %u or y %u too large\n",
		   (unsigned int)xBytes, (unsigned int) yBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_ECC;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDH;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	objectPublic->publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
	objectPublic->publicArea.parameters.eccDetail.curveID = curveID;
	objectPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	objectPublic->publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;

	objectPublic->publicArea.unique.ecc.x.t.size = xBytes;
	memcpy(objectPublic->publicArea.unique.ecc.x.t.buffer, xBin, xBytes);

	objectPublic->publicArea.unique.ecc.y.t.size = yBytes;
	memcpy(objectPublic->publicArea.unique.ecc.y.t.buffer, yBin, yBytes);
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaPublicKeyBinToPublic() converts a public modulus to a TPM2B_PUBLIC structure. */

#ifdef TPM_TPM20

TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
				      int			keyType,
				      TPMI_ALG_SIG_SCHEME 	scheme,
				      TPMI_ALG_HASH 		nalg,
				      TPMI_ALG_HASH		halg,
				      int 			modulusBytes,
				      uint8_t 			*modulusBin)
{
    TPM_RC 		rc = 0;

    if (rc == 0) {
	if ((size_t)modulusBytes > sizeof(objectPublic->publicArea.unique.rsa.t.buffer)) {
	    printf("convertRsaPublicKeyBinToPublic: Error, "
		   "public key modulus %d greater than %lu\n", modulusBytes,
		   (unsigned long)sizeof(objectPublic->publicArea.unique.rsa.t.buffer));
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_RSA;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = scheme;
	objectPublic->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	objectPublic->publicArea.parameters.rsaDetail.keyBits = modulusBytes * 8;
	objectPublic->publicArea.parameters.rsaDetail.exponent = 0;

	objectPublic->publicArea.unique.rsa.t.size = modulusBytes;
	memcpy(objectPublic->publicArea.unique.rsa.t.buffer, modulusBin, modulusBytes);
    }
    return rc;
}

#endif /* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivate() converts an mbedtls_ecp_keypair token to either a TPM2B_PRIVATE or
   TPM2B_SENSITIVE
*/

static TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				    TPM2B_SENSITIVE 	*objectSensitive,
				    mbedtls_ecp_keypair *ecKp,
				    const char 		*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an mbedtls_ecp_keypair private key to a binary array */
    if (rc == 0) {
	rc = convertEcKeyToPrivateKeyBin(&privateKeyBytes,
					 &privateKeyBin,	/* freed @1 */
					 ecKp);
    }
    /* convert the array to a TPM structure */
    if (rc == 0) {
	rc = convertEcPrivateKeyBinToPrivate(objectPrivate,
					     objectSensitive,
					     privateKeyBytes,
					     privateKeyBin,
					     password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */

/* convertRsaKeyToPrivate() converts an mbedtls_rsa_context RSA key token to either a TPM2B_PRIVATE
   or TPM2B_SENSITIVE

*/

#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

static TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				     TPM2B_SENSITIVE 	*objectSensitive,
				     mbedtls_rsa_context *rsaCtx,
				     const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an mbedtls_rsa_context RSA key token private prime p to a binary array */
    if (rc == 0) {
	rc = convertRsaKeyToPrivateKeyBin(&privateKeyBytes,
					  &privateKeyBin,	/* freed @1 */
					  rsaCtx);
    }
    /* convert an RSA prime 'privateKeyBin' to either a TPM2B_PRIVATE or a TPM2B_SENSITIVE */
    if (rc == 0) {
	rc = convertRsaPrivateKeyBinToPrivate(objectPrivate,
					      objectSensitive,
					      privateKeyBytes,
					      privateKeyBin,
					      password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublic() converts an mbedtls_ecp_keypair to a TPM2B_PUBLIC */

static TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 	*objectPublic,
				   int			keyType,
				   TPMI_ALG_SIG_SCHEME 	scheme,
				   TPMI_ALG_HASH 	nalg,
				   TPMI_ALG_HASH	halg,
				   mbedtls_ecp_keypair 	*ecKp)
{
    TPM_RC 		rc = 0;
    size_t		xBytes;
    uint8_t 		*xBin = NULL;
    size_t		yBytes;
    uint8_t 		*yBin = NULL;
    TPMI_ECC_CURVE	curveID;
    mbedtls_ecp_group 	*grp;

    /* convert an mbedtls_ecp_keypair token to a binary arrays X and Y */
    if (rc == 0) {
	rc = convertEcKeyToPublicKeyXYBin(&xBytes,
					  &xBin, 		/* freed @1 */
					  &yBytes,
					  &yBin,		/* freed @2 */
					  ecKp);
    }
    if (rc == 0) {
	int 	privateKeyBytes;
	grp = &(ecKp->private_grp);		/* get the group from the keypair */
	rc = getEcCurve(&curveID, &privateKeyBytes, grp);	/* map mbedtls to TPM */
    }
    /* converts the EC X and Y points and other parameters to a TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertEcPublicKeyXYBinToPublic(objectPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   curveID,
					   xBytes,
					   xBin,
					   yBytes,
					   yBin);
    }
    free(xBin);		/* @1 */
    free(yBin);		/* @2 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */

/* convertRsaKeyToPublic() converts from an RSA key token to a TPM2B_PUBLIC

   The parameter is void because the structure is opaque to the caller.  This accommodates other
   crypto libraries.

   rsaKey is an mbedtls_rsa_context.
*/

#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     void		 	*rsaKey)
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;

    /* mbedtls RSA key token to a public modulus */
    if (rc == 0) {
	rc = convertRsaKeyToPublicKeyBin(&modulusBytes,
					 &modulusBin,		/* freed @1 */
					 rsaKey);
    }
    /* public modulus to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaPublicKeyBinToPublic(objectPublic,
					    keyType,
					    scheme,
					    nalg,
					    halg,
					    modulusBytes,
					    modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif 	/* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToKeyPair() converts a PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertEcPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_PRIVATE 		*objectPrivate,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename,
			     const char 		*password)
{
    TPM_RC 		rc = 0;
    mbedtls_pk_context	*pkCtx = NULL;
    mbedtls_ecp_keypair *ecKp = NULL;		/* public key, EC format */

    /* convert a PEM file to an mbedtls_pk_context key pair */
    if (rc == 0) {
	rc = convertPemToPk(&pkCtx,		/* freed @1 */
			    pemKeyFilename,
			    password,
			    FALSE);		/* key pair */
    }
    /* get the mbedtls_ecp_keypair from the mbedtls_pk_context */
    if (rc == 0) {
	rc = convertPkToEckey(&ecKp, pkCtx);
    }
    /* mbedtls_ecp_keypair to TPM2B_PRIVATE */
    if (rc == 0) {
	rc = convertEcKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				   NULL,		/* TPM2B_SENSITIVE */
				   ecKp,
				   password);
    }
    /* mbedtls_ecp_keypair to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKp);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef 	TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToPublic() converts an ECC signing public key in PEM format to a
   TPM2B_PUBLIC */

TPM_RC convertEcPemToPublic(TPM2B_PUBLIC 	*objectPublic,
			    int			keyType,
			    TPMI_ALG_SIG_SCHEME scheme,
			    TPMI_ALG_HASH 	nalg,
			    TPMI_ALG_HASH	halg,
			    const char		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    mbedtls_pk_context *pkCtx = NULL;
    mbedtls_ecp_keypair *ecKp = NULL;		/* public key, EC format */

    /* convert a PEM file to an mbedtls_pk_context public key */
    if (rc == 0) {
	rc = convertPemToPk(&pkCtx,		/* freed @1 */
			    pemKeyFilename,
			    NULL,		/* password not used */
			    TRUE);		/* public */
    }
    /* get the mbedtls_ecp_keypair from the mbedtls_pk_context */
    if (rc == 0) {
	rc = convertPkToEckey(&ecKp, pkCtx);
    }
    /* mbedtls_ecp_keypair to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKp);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOFILE */
#endif	/* TPM_TPM20 */
#endif	/* TPM_TSS_NOECC */


#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaPemToKeyPair() converts an RSA PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_PRIVATE 		*objectPrivate,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char 		*pemKeyFilename,
			      const char 		*password)
{
    TPM_RC 	rc = 0;
    mbedtls_pk_context *pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;

    /* convert PEM file to mbedtls_pk_context key pair */
    if (rc == 0) {
	rc = convertPemToPk(&pkCtx,		/* freed @1 */
			    pemKeyFilename,
			    password,
			    FALSE);		/* key pair */

    }
    /* validate that it is an RSA key, and return the RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(&rsaCtx, pkCtx);
    }
    /* mbedtls_rsa_context to TPM2B_PRIVATE */
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				    NULL,		/* TPM2B_SENSITIVE */
				    rsaCtx,
				    password);
    }
    /* mbedtls_rsa_context to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaCtx);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif 	/* TPM_TPM20 */
#endif 	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcDerToKeyPair() converts an EC keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertEcDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_SENSITIVE 		*objectSensitive,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename,
			     const char 		*password)
{
    TPM_RC		rc = 0;
    int			irc;
    mbedtls_pk_context	*pkCtx = NULL;
    mbedtls_ecp_keypair *ecKp = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* allocate and initialize the key context */
    if (rc == 0) {
	rc = pkContextNew(&pkCtx);			/* freed @1 */
    }
    /* read and map the private key */
    if (rc == 0) {
	mbedtls_ctr_drbg_init(&ctr_drbg);
	irc = mbedtls_pk_parse_keyfile(pkCtx,
				       derKeyFilename,
				       password,
				       mbedtls_ctr_drbg_random, &ctr_drbg);
	if (irc != 0) {
	    printf("convertEcDerToKeyPair: Error in mbedtls_pk_parse_keyfile()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the mbedtls_ecp_keypair from the mbedtls_pk_context */
    if (rc == 0) {
	rc = convertPkToEckey(&ecKp, pkCtx);
    }
    /* mbedtls_ecp_keypair to TPM2B_PRIVATE */
    if (rc == 0) {
	rc = convertEcKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				   objectSensitive,	/* TPM2B_SENSITIVE */
				   ecKp,
				   password);
    }
    /* mbedtls_ecp_keypair to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKp);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

/* convertEcDerToPublic() converts an EC public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

#ifndef TPM_TSS_NOFILE
#ifdef 	TPM_TPM20
#ifndef TPM_TSS_NOECC

TPM_RC convertEcDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			    int				keyType,
			    TPMI_ALG_SIG_SCHEME 	scheme,
			    TPMI_ALG_HASH 		nalg,
			    TPMI_ALG_HASH		halg,
			    const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
    int			irc;
    mbedtls_pk_context	*pkCtx = NULL;
    mbedtls_ecp_keypair *ecKp = NULL;

    /* allocate and initialize the key context */
    if (rc == 0) {
	rc = pkContextNew(&pkCtx);			/* freed @1 */
    }
    /* read and map the public key */
    if (rc == 0) {
	irc = mbedtls_pk_parse_public_keyfile(pkCtx, derKeyFilename);
	if (irc != 0) {
	    printf("convertEcDerToKeyPair: Error in mbedtls_pk_parse_public_keyfile()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the mbedtls_ecp_keypair from the mbedtls_pk_context */
    if (rc == 0) {
	rc = convertPkToEckey(&ecKp, pkCtx);
    }
    /* mbedtls_ecp_keypair to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKp);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif/* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaDerToKeyPair() converts an RSA keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertRsaDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_SENSITIVE 		*objectSensitive,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char		*derKeyFilename,
			      const char 		*password)
{
    TPM_RC		rc = 0;
    int			irc;
    mbedtls_pk_context 	*pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;

    /* allocate and initialize the key context */
    if (rc == 0) {
	rc = pkContextNew(&pkCtx);		/* freed @2 */
    }
    /* read and map the private key */
    if (rc == 0) {
	mbedtls_ctr_drbg_init(&ctr_drbg);
	irc = mbedtls_pk_parse_keyfile(pkCtx,
				       derKeyFilename,
				       password,
				       mbedtls_ctr_drbg_random, &ctr_drbg);
	if (irc != 0) {
	    printf("convertRsaDerToKeyPair: Error in mbedtls_pk_parse_keyfile()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* validate that it is an RSA key, and return the RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(&rsaCtx, pkCtx);
    }
    /* mbedtls_rsa_context to TPM2B_PRIVATE */
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				    objectSensitive,	/* TPM2B_SENSITIVE */
				    rsaCtx,
				    password);
    }
    /* mbedtls_rsa_context to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaCtx);
    }
    pkContextFree(pkCtx);		/* @2 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif 	/* TPM_TPM20 */
#endif 	/* TPM_TSS_NOFILE */


#ifndef  TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaDerToPublic() converts an RSA public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

TPM_RC convertRsaDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
    int			irc;
    mbedtls_pk_context 	*pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;

    /* allocate and initialize the key context */
    if (rc == 0) {
	rc = pkContextNew(&pkCtx);		/* freed @1 */
    }
    /* read and map the public key */
    if (rc == 0) {
	irc = mbedtls_pk_parse_public_keyfile(pkCtx, derKeyFilename);
	if (irc != 0) {
	    printf("convertRsaDerToPublic: Error in mbedtls_pk_parse_public_keyfile()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* validate that it is an RSA key, and return the RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(&rsaCtx, pkCtx);
    }
    /* mbedtls_rsa_context to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaCtx);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaPemToPublic() converts an RSA public key in PEM format to a TPM2B_PUBLIC */

TPM_RC convertRsaPemToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    mbedtls_pk_context *pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;

    /* convert PEM file to mbedtls_pk_context public key */
    if (rc == 0) {
	rc = convertPemToPk(&pkCtx,		/* freed @1 */
			    pemKeyFilename,
			    NULL,		/* password */
			    TRUE);		/* public key */
    }
    /* validate that it is an RSA key, and return the RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(&rsaCtx, pkCtx);
    }
    /* mbedtls_rsa_context to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaCtx);
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

/* getRsaKeyParts() gets the RSA key parts from an mbedtls RSA key token.

*/

#ifndef TPM_TSS_NORSA

/* getRsaKeyParts() extracts the requested mbedtls_mpi key parts from the mbedtls_rsa_context

 */

static TPM_RC getRsaKeyParts(mbedtls_mpi *n,	/* freed by caller */
			     mbedtls_mpi *e,	/* freed by caller */
			     mbedtls_mpi *d,	/* freed by caller */
			     mbedtls_mpi *p,	/* freed by caller */
			     mbedtls_mpi *q,	/* freed by caller */
			     const mbedtls_rsa_context *rsaCtx)
{
    TPM_RC  	rc = 0;
    int		irc;

    if (rc == 0) {
	if (n != NULL) {
	    mbedtls_mpi_init(n);
	}
	if (e != NULL) {
	    mbedtls_mpi_init(e);
	}
	if (d != NULL) {
	    mbedtls_mpi_init(d);
	}
	if (p != NULL) {
	    mbedtls_mpi_init(p);
	}
	if (q != NULL) {
	    mbedtls_mpi_init(q);
	}
	irc = mbedtls_rsa_export(rsaCtx,
				 n,p,q,d,e);
	if (irc != 0) {
	    printf("getRsaKeyParts: Error in mbedtls_rsa_export()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* convertPublicToPEM() saves a PEM format public key from a TPM2B_PUBLIC

*/

TPM_RC convertPublicToPEM(const TPM2B_PUBLIC *public,
			  const char *pemFilename)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_pk_context 	*mbedPubkey = NULL;
    unsigned char	*buffer = NULL;

    /* convert TPM2B_PUBLIC to mbedtls_pk_context */
    if (rc == 0) {
	switch (public->publicArea.type) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSA:
	    rc = convertRsaPublicToMbedPubKey(&mbedPubkey,	/* freed @1 */
					      &public->publicArea.unique.rsa);
	    break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECC:
	    rc = convertEcPublicToMbedPubKey(&mbedPubkey,	/* freed @1 */
					     &public->publicArea);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("convertPublicToPEM: Unknown publicArea.type %04hx unsupported\n",
		   public->publicArea.type);
	    rc = TSS_RC_NOT_IMPLEMENTED;
	    break;
	}
    }
    /* mbedtls doesn't have an API yet to determine the buffer size, so malloc a large buffer and
       hope for the best */
    if (rc == 0) {
	rc = TSS_Malloc(&buffer, 0x10000);	/* freed @2 */
    }
    /* write the mbedtls_pk_context public key structure in PEM format */
    if (rc == 0) {
	irc = mbedtls_pk_write_pubkey_pem(mbedPubkey, buffer, 0x10000);
	if (irc != 0) {
	    printf("convertPublicToPEM: Error in mbedtls_pk_write_pubkey_pem()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    /* write the buffer to the PEM file */
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(buffer, strlen((char *)buffer), pemFilename);
    }
    pkContextFree(mbedPubkey);	/* @1 */
    free(buffer);		/* @2 */
    return rc;
}

#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaPublicToMbedPubKey() converts an RSA TPM2B_PUBLIC to an mbedtls_pk_context public key
   token.  */

static TPM_RC convertRsaPublicToMbedPubKey(mbedtls_pk_context **mbedPubkey,	/* freed by caller */
					   const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa)
{
    TPM_RC 	rc = 0;

    /* TPM to mbedtls_rsa_context RSA key token */
    if (rc == 0) {
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	rc = TSS_RSAGeneratePublicTokenI
	     ((void **)mbedPubkey,		/* freed by caller */
	      tpm2bRsa->t.buffer,  		/* public modulus */
	      tpm2bRsa->t.size,
	      earr,      			/* public exponent */
	      sizeof(earr));
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */

#ifndef TPM_TSS_NOECC

/* convertEcPublicToMbedPubKey() converts an EC TPMS_ECC_POINT to an mbedtls_pk_context public key
   token.
 */

static TPM_RC convertEcPublicToMbedPubKey(mbedtls_pk_context **mbedPubkey,	/* freed by caller */
					  const TPMT_PUBLIC *tpmtPublic)
{
    TPM_RC 			rc = 0;
    int				irc;
    const mbedtls_pk_info_t 	*pkInfo = NULL;
    mbedtls_ecp_keypair 	*keypair = NULL;
    mbedtls_ecp_group 		*grp = NULL;
    mbedtls_ecp_group_id 	groupid = MBEDTLS_ECP_DP_NONE;
    mbedtls_ecp_point 		*pt = NULL;
    mbedtls_mpi 		*X = NULL;
    mbedtls_mpi 		*Y = NULL;
    mbedtls_mpi 		*Z = NULL;

    /*
      mbedtls_pk_context
    */
    if (rc == 0) {
	rc = pkContextNew(mbedPubkey);	/* freed by caller */
    }
    /* pk_info for ECKEY */
    if (rc == 0) {
	pkInfo = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
	if (pkInfo == NULL) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_pk_info_from_type()\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* Set up the mbedtls_pk_context for EC Public Key */
    if (rc == 0) {
	irc = mbedtls_pk_setup(*mbedPubkey, pkInfo);
	if (irc != 0) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_pk_setup()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /*
      mbedtls_ecp_keypair has a group and point Q
    */
    /* get the mbedtls_ecp_keypair here */
    if (rc == 0) {
	keypair = mbedtls_pk_ec(**mbedPubkey); /* quick access */
	/* initialize the keypair */
	mbedtls_ecp_keypair_init(keypair);
    }
    /*
      mbedtls_ecp_group grp is hard coded to NIST P-256
    */
    if (rc == 0) {
	/* get the mbedtls_ecp_group member from mbedtls_ecp_keypair */
	grp = &(keypair->private_grp);
	/* map the TCG curveID ot the mbedtls mbedtls_ecp_group_id */
	rc = getEcGroupID(&groupid,
			  tpmtPublic->parameters.eccDetail.curveID);	/* TCG curveID */
    }
    if (rc == 0) {
	/* initialize the mbedtls_ecp_group */
	mbedtls_ecp_group_init(grp);
	/*  Setup the group based on curve name */
	irc = mbedtls_ecp_group_load(grp, groupid);
	if (irc != 0) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_ecp_group_load()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /*
      mbedtls_ecp_point	Q has coordinates X Y Z
    */
    if (rc == 0) {
	/* get the mbedtls_ecp_point member from the mbedtls_ecp_keypair */
	pt = &(keypair->private_Q);
	/* initialize the mbedtls_ecp_point */
	mbedtls_ecp_point_init(pt);
	/* a point has mbedtls_mpi X and mbedtls_mpi Y */
    }
    /*
      X and Y points
    */
    /* get the X, Y, Z members of the public point Q */
    if (rc == 0) {
	X = &(pt->private_X);
	Y = &(pt->private_Y);
	Z = &(pt->private_Z);
    }
    /* TPM byte array to mbedtls_mpi */
    if (rc == 0) {
	irc = mbedtls_mpi_read_binary(X,
				      tpmtPublic->unique.ecc.x.t.buffer,
				      tpmtPublic->unique.ecc.x.t.size);
	if (irc != 0) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_mpi_read_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = mbedtls_mpi_read_binary(Y,
				      tpmtPublic->unique.ecc.y.t.buffer,
				      tpmtPublic->unique.ecc.y.t.size);
	if (irc != 0) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_mpi_read_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* All functions expect and return points satisfying the following condition: Z == 0 or Z ==
       1. Other values of Z are used only by internal functions. The point is zero, or "at
       infinity", if Z == 0. Otherwise, X and Y are its standard (affine) coordinates. */
    if (rc == 0) {
	uint8_t ztmp = 1;
	irc = mbedtls_mpi_read_binary(Z, &ztmp, 1);
	if (irc != 0) {
	    printf("convertEcPublicToMbedPubKey: Error in mbedtls_mpi_read_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* verifySignatureFromPem() verifies the signature 'tSignature' against the digest 'message' using
   the public key in the PEM format file 'pemFilename'.

*/

TPM_RC verifySignatureFromPem(unsigned char *message,
			      unsigned int messageSize,
			      TPMT_SIGNATURE *tSignature,
			      TPMI_ALG_HASH halg,
			      const char *pemFilename)
{
    TPM_RC 			rc = 0;
    mbedtls_pk_context 		*pkCtx = NULL;

    /* convert a PEM file to an mbedtls_pk_context public key */
    if (rc == 0) {
	rc = convertPemToPk(&pkCtx,		/* freed @1*/
			    pemFilename,
			    NULL,		/* password */
			    TRUE);		/* public key */
    }
    /* RSA or EC */
    if (rc == 0) {
	switch(tSignature->sigAlg) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSASSA:
	  case TPM_ALG_RSAPSS:
	    rc = verifyRSASignatureFromPk(message,
					  messageSize,
					  tSignature,
					  halg,
					  pkCtx);
	    break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECDSA:
	    rc = verifyEcSignatureFromPk(message,
					 messageSize,
					 tSignature,
					 pkCtx);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("verifySignatureFromPem: Unknown signature algorithm %04x\n",
		   tSignature->sigAlg);
	    rc = TSS_RC_BAD_SIGNATURE_ALGORITHM;
	}
    }
    pkContextFree(pkCtx);		/* @1 */
    return rc;
}

#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

/* verifyRSASignatureFromPk() verifies the signature 'tSignature' against the digest 'message' using
   the mbedtls_pk_context RSA public key in pkCtx.

*/

#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

static TPM_RC verifyRSASignatureFromPk(unsigned char *message,
				       unsigned int messageSize,
				       TPMT_SIGNATURE *tSignature,
				       TPMI_ALG_HASH halg,
				       mbedtls_pk_context *pkCtx)
{
    TPM_RC 		rc = 0;

    /* validate that it is an RSA key */
    if (rc == 0) {
	rc = convertPkToRsaKey(NULL, pkCtx);
    }
    /* verify the signature */
    if (rc == 0) {
	rc = verifyRSASignatureFromRSA(message,
				       messageSize,
				       tSignature,
				       halg,
				       pkCtx);
    }
    return rc;
}

#endif	/* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */


/* signRSAFromRSA() signs digest to signature, using the RSA key rsaKey.

   rsaKey is an mbedtls_pk_context

 */

#ifndef TPM_TSS_NORSA

TPM_RC signRSAFromRSA(uint8_t *signature, size_t *signatureLength,
		      size_t signatureSize,
		      const uint8_t *digest, size_t digestLength,
		      TPMI_ALG_HASH hashAlg,
		      void *rsaKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_md_type_t 	mdAlg;			/* mbedtls hash algorithm */
    size_t 		keySize;		/* public modulus */
    mbedtls_pk_context  *pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    /* map the hash algorithm to the mbedtls message digest algorithm */
    if (rc == 0) {
	rc = convertTpmHalgToMd(&mdAlg, hashAlg);
    }
    if (rc == 0) {
	pkCtx = (mbedtls_pk_context*)rsaKey;
	rsaCtx = mbedtls_pk_rsa(*pkCtx);	/* access wrapped RSA key */
    }
    /* validate that the length of the resulting signature will fit in the
       signature array */
    if (rc == 0) {
	keySize = mbedtls_rsa_get_len(rsaCtx);
	if (keySize > signatureSize) {
	    printf("signRSAFromRSA: Error, private key length %u > signature buffer %u\n",
		   (unsigned int)keySize, (unsigned int)signatureSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* sign digest using the RSA key rsaCtx */
    if (rc == 0) {
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	irc = mbedtls_ctr_drbg_seed(&ctr_drbg,
				    mbedtls_entropy_func,
				    &entropy,
				    NULL,
				    MBEDTLS_CTR_DRBG_ENTROPY_LEN);
	if (irc != 0) {
	    printf("signRSAFromRSA: Error in mbedtls_ctr_drbg_seed()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = mbedtls_rsa_set_padding(rsaCtx, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
	if (irc != 0) {
	    printf("signRSAFromRSA: Error in mbedtls_rsa_set_padding()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = mbedtls_rsa_pkcs1_sign(rsaCtx,
				     mbedtls_ctr_drbg_random, &ctr_drbg,
				     mdAlg,
				     digestLength,
				     digest,
				     signature);
	*signatureLength = keySize;
	if (irc != 0) {
	    printf("signRSAFromRSA: Error in mbedtls_rsa_pkcs1_sign()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NORSA */

/* verifyRSASignatureFromRSA() verifies the signature 'tSignature' against the digest 'message'
   using the RSA public key in the mbedtls RSA format.

   Supports RSASSA and RSAPSS schemes.

   rsaPubKey is an mbedtls_pk_context
*/

#ifndef TPM_TSS_NORSA

TPM_RC verifyRSASignatureFromRSA(unsigned char *message,
				 unsigned int messageSize,
				 TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH hashAlg,
				 void *rsaPubKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_md_type_t 	mdAlg;			/* mbedtls hash algorithm */
    size_t 		keySize;		/* public modulus */
    mbedtls_pk_context  *pkCtx = NULL;
    mbedtls_rsa_context *rsaCtx = NULL;

    /* map from hash algorithm to mbedtls message digest */
    if (rc == 0) {
	rc = convertTpmHalgToMd(&mdAlg, hashAlg);
    }
    if (rc == 0) {
	pkCtx = (mbedtls_pk_context*)rsaPubKey;
	rsaCtx = mbedtls_pk_rsa(*pkCtx);	/* access wrapped RSA key */
    }
    /* validate that the length of the signature matches the public key size */
    if (rc == 0) {
	keySize = mbedtls_rsa_get_len(rsaCtx);
	if (keySize != tSignature->signature.rsassa.sig.t.size) {
	    printf("verifyRSASignatureFromRSA: Error, private key length %u > signature buffer %u\n",
		   (unsigned int)keySize, (unsigned int)tSignature->signature.rsassa.sig.t.size);
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
   /* verify the signature */
    if (tSignature->sigAlg == TPM_ALG_RSASSA) {
	if (rc == 0) {
	    irc = mbedtls_rsa_rsassa_pkcs1_v15_verify(rsaCtx,
						      mdAlg,
						      messageSize, message,
						      tSignature->signature.rsassa.sig.t.buffer);

	    if (irc != 0) {
		printf("verifyRSASignatureFromRSA: Bad RSASSA signature\n");
		mbedtlsError(irc);
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else if (tSignature->sigAlg == TPM_ALG_RSAPSS) {
	if (rc == 0) {
	    irc = mbedtls_rsa_rsassa_pss_verify(rsaCtx,
						mdAlg,
						messageSize, message,
						tSignature->signature.rsassa.sig.t.buffer);
	    if (irc != 0) {
		printf("verifyRSASignatureFromRSA: Bad RSAPSS signature\n");
		mbedtlsError(irc);
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else {
	printf("verifyRSASignatureFromRSA: Bad signature scheme %04x\n",
	       tSignature->sigAlg);
    }
    return rc;
}

#endif	/* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* verifyEcSignatureFromPk() verifies the signature 'tSignature' against the digest 'message'
   using the EC public key in pkCtx.
*/

static TPM_RC verifyEcSignatureFromPk(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      mbedtls_pk_context *pkCtx)
{
    TPM_RC 		rc = 0;
    mbedtls_ecp_keypair *ecCtx = NULL;		/* public key, EC format */

    /* get the mbedtls_ecp_keypair from the mbedtls_pk_context */
    if (rc == 0) {
	rc = convertPkToEckey(&ecCtx, pkCtx);
    }
    /* verify the signature 'tSignature' over 'message' */
    if (rc == 0) {
	rc = verifyEcSignatureFromEc(message,
				     messageSize,
				     tSignature,
				     ecCtx);
    }
    return rc;
}

/* verifyEcSignatureFromEc() verifies the signature 'tSignature' against the digest 'message'
   using the EC public key in the mbedtls mbedtls_ecp_keypair format.

   ecPubKey is an mbedtls_ecp_keypair
*/

static TPM_RC verifyEcSignatureFromEc(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      mbedtls_ecp_keypair *ecPubKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_ecp_group 	*grp;
    mbedtls_ecp_point 	*Q;
    mbedtls_mpi 	r;
    mbedtls_mpi 	s;

    /* from the public key, get grp, and public point Q */
    if (rc == 0) {
	grp = &(ecPubKey->private_grp);
	Q = &(ecPubKey->private_Q);
    }
    /* from the TPMT_SIGNATURE, create r and s */
    if (rc == 0) {
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
    }
    if (rc == 0) {
	irc = mbedtls_mpi_read_binary(&r,	/* freed @1 */
				      tSignature->signature.ecdsa.signatureR.t.buffer,
				      tSignature->signature.ecdsa.signatureR.t.size);
	if (irc != 0) {
	    printf("verifyEcSignatureFromEc: Error in mbedtls_mpi_read_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	irc = mbedtls_mpi_read_binary(&s,	/* freed @2 */
				      tSignature->signature.ecdsa.signatureS.t.buffer,
				      tSignature->signature.ecdsa.signatureS.t.size);
	if (irc != 0) {
	    printf("verifyEcSignatureFromEc: Error in mbedtls_mpi_read_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	irc = mbedtls_ecdsa_verify(grp,
				   message, messageSize,
				   Q,
				   &r,
				   &s);
	if (irc != 0) {
	    printf("verifyEcSignatureFromEc: Error in mbedtls_ecdsa_verify()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    mbedtls_mpi_free(&r);	/* @1 */
    mbedtls_mpi_free(&s);	/* @2 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOFILE

/* verifySignatureFromHmacKey() verifies the signature (MAC) against the digest 'message'
   using the HMAC key in raw binary format.
*/

TPM_RC verifySignatureFromHmacKey(unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  const char *hmacKeyFilename)
{
    TPM_RC 		rc = 0;
    TPM2B_KEY 		hmacKey;
    uint32_t 		sizeInBytes;

    /* read the HMAC key */
    if (rc == 0) {
	rc = TSS_File_Read2B(&hmacKey.b,
			     sizeof(hmacKey.t.buffer),
			     hmacKeyFilename);
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(halg);
	rc = TSS_HMAC_Verify(&tSignature->signature.hmac,
			     &hmacKey,		/* input HMAC key */
			     sizeInBytes,
			     messageSize, message,
			     0, NULL);
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* convertRsaBinToTSignature() converts an RSA binary signature to a TPMT_SIGNATURE */

#ifdef TPM_TPM20

TPM_RC convertRsaBinToTSignature(TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH halg,
				 const uint8_t *signatureBin,
				 size_t signatureBinLen)
{
    TPM_RC rc = 0;

    tSignature->sigAlg = TPM_ALG_RSASSA;
    tSignature->signature.rsassa.hash = halg;
    tSignature->signature.rsassa.sig.t.size = (uint16_t)signatureBinLen;
    memcpy(&tSignature->signature.rsassa.sig.t.buffer, signatureBin, signatureBinLen);
    return rc;
}

#endif /* TPM_TPM20 */

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcBinToTSignature() converts an EC binary signature (DER encoded) to a TPMT_SIGNATURE */

TPM_RC convertEcBinToTSignature(TPMT_SIGNATURE *tSignature,
				TPMI_ALG_HASH halg,
				const uint8_t *signatureBin,
				size_t signatureBinLen)
{
    TPM_RC 		rc = 0;
    int			irc;
    mbedtls_mpi 	r;			/* r and s are the ECC signature fields */
    mbedtls_mpi 	s;
    size_t 		len;
    /* cast because mbedtls does not use const */
    unsigned char 	*p = (unsigned char *)signatureBin;	/* current pointer into signature */
    const unsigned char *end = signatureBin + signatureBinLen;	/* end of signature */

    if (rc == 0) {
	tSignature->sigAlg = TPM_ALG_ECDSA;
	tSignature->signature.ecdsa.hash = halg;
    }
    if (rc == 0) {
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
    }
    /* get and check tag */
    if (rc == 0) {
	irc = mbedtls_asn1_get_tag(&p, end, &len,
				   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);	/* tag */
	if (irc != 0) {
	    printf("convertEcBinToTSignature: Error in mbedtls_asn1_get_tag()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    /* validate tag length */
    if (rc == 0) {
	if(p + len != end) {
	    printf("convertEcBinToTSignature: Error in mbedtls_asn1_get_tag()\n");
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    /* get r */
    if (rc == 0) {
	irc = mbedtls_asn1_get_mpi(&p, end, &r);	/* freed @1 */
	if (irc != 0) {
	    printf("convertEcBinToTSignature: Error in mbedtls_asn1_get_mpi()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    /* get s */
    if (rc == 0) {
	irc = mbedtls_asn1_get_mpi(&p, end, &s);	/* freed @2 */
	if (irc != 0) {
	    printf("convertEcBinToTSignature: Error in mbedtls_asn1_get_mpi()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    /* validate total length */
    if (rc == 0) {
	if( p != end) {
	    printf("convertEcBinToTSignature: Error in mbedtls_asn1_get_mpi()\n");
	    rc = TSS_RC_EC_SIGNATURE;

	}
    }
    /* get and validate the r and s sizes */
    if (rc == 0) {
	tSignature->signature.ecdsa.signatureR.t.size = mbedtls_mpi_size(&r);
	tSignature->signature.ecdsa.signatureS.t.size = mbedtls_mpi_size(&s);
	if ((tSignature->signature.ecdsa.signatureR.t.size > sizeof(tSignature->signature.ecdsa.signatureR.t.buffer)) ||
	    (tSignature->signature.ecdsa.signatureS.t.size > sizeof(tSignature->signature.ecdsa.signatureR.t.buffer))) {
	    printf("convertEcBinToTSignature: signature rBytes %u or sBytes %u greater than %u",
		   tSignature->signature.ecdsa.signatureR.t.size,
		   tSignature->signature.ecdsa.signatureS.t.size,
		   (unsigned int)sizeof(tSignature->signature.ecdsa.signatureR.t.buffer));
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    /* extract the raw signature bytes from the mbedtls_mpi r and s */
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary
	      (&r,
	       (unsigned char *)&tSignature->signature.ecdsa.signatureR.t.buffer,
	       tSignature->signature.ecdsa.signatureR.t.size);
	if (irc != 0) {
	    printf("convertEcBinToTSignature: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    if (rc == 0) {
	irc = mbedtls_mpi_write_binary
	      (&s,
	       (unsigned char *)&tSignature->signature.ecdsa.signatureS.t.buffer,
	       tSignature->signature.ecdsa.signatureS.t.size);
	if (irc != 0) {
	    printf("convertEcBinToTSignature: Error in mbedtls_mpi_write_binary()\n");
	    mbedtlsError(irc);
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) {
	    TSS_PrintAll("convertEcBinToTSignature: signature R",
			 tSignature->signature.ecdsa.signatureR.t.buffer,
			 tSignature->signature.ecdsa.signatureR.t.size);
	    TSS_PrintAll("convertEcBinToTSignature: signature S",
			 tSignature->signature.ecdsa.signatureS.t.buffer,
			 tSignature->signature.ecdsa.signatureS.t.size);
	}
    }
    mbedtls_mpi_free(&r);		/* @1 */
    mbedtls_mpi_free(&s);		/* @2 */
    return rc;
}

#endif /* TPM_TSS_NOECC */
#endif /* TPM_TPM20 */
