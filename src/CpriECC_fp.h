/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: CpriECC_fp.h 55 2015-02-05 22:03:16Z kgoldman $		*/
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

#ifndef CPRIECC_FP_H
#define CPRIECC_FP_H

LIB_EXPORT BOOL
_cpri__EccStartup(
		  void
		  );
LIB_EXPORT TPM_ECC_CURVE
_cpri__GetCurveIdByIndex(
			 UINT16           i
			 );
LIB_EXPORT UINT32
_cpri__EccGetCurveCount(
			void
			);
LIB_EXPORT const ECC_CURVE *
_cpri__EccGetParametersByCurveId(
				 TPM_ECC_CURVE    curveId        // IN: the curveID
				 );
LIB_EXPORT CRYPT_RESULT
_cpri__EccPointMultiply(
			TPMS_ECC_POINT          *Rout,          // OUT: the product point R
			TPM_ECC_CURVE            curveId,       // IN: the curve to use
			TPM2B_ECC_PARAMETER     *dIn,           // IN: value to multiply against the
			//     curve generator
			TPMS_ECC_POINT          *Qin,           // IN: point Q
			TPM2B_ECC_PARAMETER     *uIn            // IN: scalar value for the multiplier
			//     of Q
			);
LIB_EXPORT CRYPT_RESULT
_cpri__EccCommitCompute(
			TPMS_ECC_POINT          *K,             // OUT: [d]B or [r]Q
			TPMS_ECC_POINT          *L,             // OUT: [r]B
			TPMS_ECC_POINT          *E,             // OUT: [r]M
			TPM_ECC_CURVE            curveId,       // IN: the curve for the computations
			TPMS_ECC_POINT          *M,             // IN: M (optional)
			TPMS_ECC_POINT          *B,             // IN: B (optional)
			TPM2B_ECC_PARAMETER     *d,             // IN: d (required)
			TPM2B_ECC_PARAMETER     *r              // IN: the computed r value (required)
			);
LIB_EXPORT BOOL
_cpri__EccIsPointOnCurve(
			 TPM_ECC_CURVE    curveId,       // IN: the curve selector
			 TPMS_ECC_POINT   *Q             // IN: the point.
			 );
LIB_EXPORT CRYPT_RESULT
_cpri__GenerateKeyEcc(
		      TPMS_ECC_POINT          *Qout,          // OUT: the public point
		      TPM2B_ECC_PARAMETER     *dOut,          // OUT: the private scalar
		      TPM_ECC_CURVE            curveId,       // IN: the curve identifier
		      TPM_ALG_ID               hashAlg,       // IN: hash algorithm to use in the key
		      //     generation process
		      TPM2B                   *seed,          // IN: the seed to use
		      const char              *label,         // IN: A label for the generation
		      //     process.
		      TPM2B                   *extra,         // IN: Party 1 data for the KDF
		      UINT32                  *counter        // IN/OUT: Counter value to allow KDF
		      //     iteration to be propagated across
		      //     multiple functions
		      );
LIB_EXPORT CRYPT_RESULT
_cpri__GetEphemeralEcc(
		       TPMS_ECC_POINT          *Qout,          // OUT: the public point
		       TPM2B_ECC_PARAMETER     *dOut,          // OUT: the private scalar
		       TPM_ECC_CURVE            curveId        // IN: the curve for the key
		       );
LIB_EXPORT CRYPT_RESULT
SignEcdsa(
	  TPM2B_ECC_PARAMETER     *rOut,          // OUT: r component of the signature
	  TPM2B_ECC_PARAMETER     *sOut,          // OUT: s component of the signature
	  TPM_ECC_CURVE            curveId,       // IN: the curve used in the signature
	  //     process
	  TPM2B_ECC_PARAMETER     *dIn,           // IN: the private key
	  TPM2B                   *digest         // IN: the value to sign
	  );
LIB_EXPORT CRYPT_RESULT
_cpri__SignEcc(
	       TPM2B_ECC_PARAMETER     *rOut,          // OUT: r component of the signature
	       TPM2B_ECC_PARAMETER     *sOut,          // OUT: s component of the signature
	       TPM_ALG_ID               scheme,        // IN: the scheme selector
	       TPM_ALG_ID               hashAlg,       // IN: the hash algorithm if need
	       TPM_ECC_CURVE            curveId,       // IN: the curve used in the signature
	       //     process
	       TPM2B_ECC_PARAMETER     *dIn,           // IN: the private key
	       TPM2B                   *digest,        // IN: the digest to sign
	       TPM2B_ECC_PARAMETER     *kIn            // IN: k for input
	       );
LIB_EXPORT CRYPT_RESULT
_cpri__ValidateSignatureEcc(
			    TPM2B_ECC_PARAMETER     *rIn,           // IN: r component of the signature
			    TPM2B_ECC_PARAMETER     *sIn,           // IN: s component of the signature
			    TPM_ALG_ID               scheme,        // IN: the scheme selector
			    TPM_ALG_ID               hashAlg,       // IN: the hash algorithm used (not used
			    //     in all schemes)
			    TPM_ECC_CURVE            curveId,       // IN: the curve used in the signature
			    //     process
			    TPMS_ECC_POINT          *Qin,           // IN: the public point of the key
			    TPM2B                   *digest         // IN: the digest that was signed
			    );
LIB_EXPORT CRYPT_RESULT
_cpri__C_2_2_KeyExchange(
			 TPMS_ECC_POINT          *outZ1,         // OUT: a computed point
			 TPMS_ECC_POINT          *outZ2,         // OUT: and optional second point
			 TPM_ECC_CURVE            curveId,       // IN: the curve for the computations
			 TPM_ALG_ID               scheme,        // IN: the key exchange scheme
			 TPM2B_ECC_PARAMETER     *dsA,           // IN: static private TPM key
			 TPM2B_ECC_PARAMETER     *deA,           // IN: ephemeral private TPM key
			 TPMS_ECC_POINT          *QsB,           // IN: static public party B key
			 TPMS_ECC_POINT          *QeB            // IN: ephemeral public party B key
			 );
			


#endif
