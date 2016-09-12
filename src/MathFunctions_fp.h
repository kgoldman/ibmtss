/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: MathFunctions_fp.h 55 2015-02-05 22:03:16Z kgoldman $	*/
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

#ifndef MATHFUNCTIONS_FP_H
#define MATHFUNCTIONS_FP_H

LIB_EXPORT UINT16
_math__Normalize2B(
		   TPM2B           *b              // IN/OUT: number to normalize
		   );
LIB_EXPORT BOOL
_math__Denormalize2B(
		     TPM2B           *in,            // IN:OUT TPM2B number to de-normalize
		     UINT32           size           // IN: the desired size
		     );
LIB_EXPORT int
_math__sub(
	   const UINT32     aSize,         // IN: size of a
	   const BYTE      *a,             // IN: a
	   const UINT32     bSize,         // IN: size of b
	   const BYTE      *b,             // IN: b
	   UINT16          *cSize,         // OUT: set to MAX(aSize, bSize)
	   BYTE            *c              // OUT: the difference
	   );
LIB_EXPORT int
_math__Inc(
	   UINT32           aSize,         // IN: size of a
	   BYTE            *a              // IN: a
	   );
LIB_EXPORT void
_math__Dec(
	   UINT32           aSize,         // IN: size of a
	   BYTE            *a              // IN: a
	   );
LIB_EXPORT int
_math__Mul(
	   const UINT32     aSize,         // IN: size of a
	   const BYTE      *a,             // IN: a
	   const UINT32     bSize,         // IN: size of b
	   const BYTE      *b,             // IN: b
	   UINT32          *pSize,         // IN/OUT: size of the product
	   BYTE            *p              // OUT: product. length of product = aSize +
	   //     bSize
	   );
LIB_EXPORT CRYPT_RESULT
_math__Div(
	   const TPM2B     *n,             // IN: numerator
	   const TPM2B     *d,             // IN: denominator
	   TPM2B           *q,             // OUT: quotient
	   TPM2B           *r              // OUT: remainder
	   );
LIB_EXPORT int
_math__uComp(
	     const UINT32     aSize,         // IN: size of a
	     const BYTE      *a,             // IN: a
	     const UINT32     bSize,         // IN: size of b
	     const BYTE      *b              // IN: b
	     );
LIB_EXPORT int
_math__Comp(
	    const UINT32     aSize,         // IN: size of a
	    const BYTE      *a,             // IN: a buffer
	    const UINT32     bSize,         // IN: size of b
	    const BYTE      *b              // IN: b buffer
	    );
LIB_EXPORT CRYPT_RESULT
_math__ModExp(
	      UINT32           cSize,         // IN: size of the result
	      BYTE            *c,             // OUT: results buffer
	      const UINT32     mSize,         // IN: size of number to be exponentiated
	      const BYTE      *m,             // IN: number to be exponentiated
	      const UINT32     eSize,         // IN: size of power
	      const BYTE      *e,             // IN: power
	      const UINT32     nSize,         // IN: modulus size
	      const BYTE      *n              // IN: modulu
	      );
LIB_EXPORT BOOL
_math__IsPrime(
	       const UINT32     prime
	       );


#endif
