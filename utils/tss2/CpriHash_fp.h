/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriHash_fp.h 683 2016-07-15 20:53:46Z kgoldman $		*/
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

#ifndef CPRIHASH_FP_H
#define CPRIHASH_FP_H

#include "CryptoEngine.h"	/* added kgold */

LIB_EXPORT BOOL
_cpri__HashStartup(
		   void
		   );
LIB_EXPORT TPM_ALG_ID
_cpri__GetHashAlgByIndex(
			 UINT32           index          // IN: the index
			 );
LIB_EXPORT UINT16
_cpri__GetHashBlockSize(
			TPM_ALG_ID       hashAlg        // IN: hash algorithm to look up
			);
LIB_EXPORT UINT16
_cpri__GetHashDER(
		  TPM_ALG_ID       hashAlg,       // IN: the algorithm to look up
		  const BYTE      **p
		  );
LIB_EXPORT UINT16
_cpri__GetDigestSize(
		     TPM_ALG_ID       hashAlg        // IN: hash algorithm to look up
		     );
LIB_EXPORT TPM_ALG_ID
_cpri__GetContextAlg(
		     CPRI_HASH_STATE     *hashState      // IN: the hash context
		     );
LIB_EXPORT UINT16
_cpri__CopyHashState (
		      CPRI_HASH_STATE     *out,           // OUT: destination of the state
		      CPRI_HASH_STATE     *in             // IN: source of the state
		      );
LIB_EXPORT UINT16
_cpri__StartHash(
		 TPM_ALG_ID           hashAlg,       // IN: hash algorithm
		 BOOL                 sequence,      // IN: TRUE if the state should be saved
		 CPRI_HASH_STATE     *hashState      // OUT: the state of hash stack.
		 );
LIB_EXPORT void
_cpri__UpdateHash(
		  CPRI_HASH_STATE     *hashState,     // IN: the hash context information
		  UINT32               dataSize,      // IN: the size of data to be added to the
		  //     digest
		  BYTE                *data           // IN: data to be hashed
		  );
LIB_EXPORT UINT16
_cpri__CompleteHash(
		    CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
		    UINT32               dOutSize,      // IN: size of digest buffer
		    BYTE                *dOut           // OUT: hash digest
		    );
LIB_EXPORT void
_cpri__ImportExportHashState(
			     CPRI_HASH_STATE     *osslFmt,       // IN/OUT: the hash state formated for use
			     //     by openSSL
			     EXPORT_HASH_STATE   *externalFmt,   // IN/OUT: the exported hash state
			     IMPORT_EXPORT        direction      //
			     );
LIB_EXPORT UINT16
_cpri__HashBlock(
		 TPM_ALG_ID       hashAlg,       // IN: The hash algorithm
		 UINT32           dataSize,      // IN: size of buffer to hash
		 BYTE            *data,          // IN: the buffer to hash
		 UINT32           digestSize,    // IN: size of the digest buffer
		 BYTE            *digest         // OUT: hash digest
		 );
LIB_EXPORT UINT16
_cpri__StartHMAC(
		 TPM_ALG_ID           hashAlg,       // IN: the algorithm to use
		 BOOL                 sequence,      // IN: indicates if the state should be
		 //     saved
		 CPRI_HASH_STATE     *state,         // IN/OUT: the state buffer
		 UINT16               keySize,       // IN: the size of the HMAC key
		 BYTE                *key,           // IN: the HMAC key
		 TPM2B               *oPadKey        // OUT: the key prepared for the oPad round
		 );
LIB_EXPORT UINT16
_cpri__CompleteHMAC(
		    CPRI_HASH_STATE     *hashState,     // IN: the state of hash stack
		    TPM2B               *oPadKey,       // IN: the HMAC key in oPad format
		    UINT32               dOutSize,      // IN: size of digest buffer
		    BYTE                *dOut           // OUT: hash digest
		    );
LIB_EXPORT CRYPT_RESULT
_cpri__MGF1(
	    UINT32           mSize,         // IN: length of the mask to be produced
	    BYTE            *mask,          // OUT: buffer to receive the mask
	    TPM_ALG_ID       hashAlg,       // IN: hash to use
	    UINT32           sSize,         // IN: size of the seed
	    BYTE            *seed           // IN: seed size
	    );
LIB_EXPORT UINT16
_cpri__KDFa(
	    TPM_ALG_ID       hashAlg,       // IN: hash algorithm used in HMAC
	    TPM2B           *key,           // IN: HMAC key
	    const char      *label,         // IN: a 0-byte terminated label used in KDF
	    TPM2B           *contextU,      // IN: context U
	    TPM2B           *contextV,      // IN: context V
	    UINT32           sizeInBits,    // IN: size of generated key in bit
	    BYTE            *keyStream,     // OUT: key buffer
	    UINT32          *counterInOut,  // IN/OUT: caller may provide the iteration
	    //     counter for incremental operations to
	    //     avoid large intermediate buffers.
	    BOOL             once           // IN: TRUE if only one iteration is performed
	    //     FALSE if iteration count determined by
	    //     "sizeInBits"
	    );
LIB_EXPORT UINT16
_cpri__KDFe(
	    TPM_ALG_ID       hashAlg,       // IN: hash algorithm used in HMAC
	    TPM2B           *Z,             // IN: Z
	    const char      *label,         // IN: a 0 terminated label using in KDF
	    TPM2B           *partyUInfo,    // IN: PartyUInfo
	    TPM2B           *partyVInfo,    // IN: PartyVInfo
	    UINT32           sizeInBits,    // IN: size of generated key in bit
	    BYTE            *keyStream      // OUT: key buffer
	    );


#endif
