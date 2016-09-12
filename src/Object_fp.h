/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Object_fp.h 471 2015-12-22 19:40:24Z kgoldman $		*/
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

/* rev 124 */

#ifndef OBJECT_FP_H
#define OBJECT_FP_H

void
ObjectStartup(
	      void
	      );
void
ObjectCleanupEvict(
		   void
		   );
BOOL
ObjectIsPresent(
		TPMI_DH_OBJECT   handle         // IN: handle to be checked
		);
BOOL
ObjectIsSequence(
		 OBJECT          *object         // IN: handle to be checked
		 );
OBJECT*
ObjectGet(
	  TPMI_DH_OBJECT   handle         // IN: handle of the object
	  );
UINT16
ObjectGetName(
	      TPMI_DH_OBJECT   handle,        // IN: handle of the object
	      NAME            *name           // OUT: name of the object
	      );
TPMI_ALG_HASH
ObjectGetNameAlg(
		 TPMI_DH_OBJECT   handle         // IN: handle of the object
		 );
void
ObjectGetQualifiedName(
		       TPMI_DH_OBJECT   handle,        // IN: handle of the object
		       TPM2B_NAME      *qualifiedName  // OUT: qualified name of the object
		       );
TPMI_RH_HIERARCHY
ObjectDataGetHierarchy(
		       OBJECT          *object         // IN :object
		       );
TPMI_RH_HIERARCHY
ObjectGetHierarchy(
		   TPMI_DH_OBJECT   handle         // IN :object handle
		   );
TPM_RC
ObjectLoad(
	   TPMI_RH_HIERARCHY    hierarchy,     // IN: hierarchy to which the object belongs
	   TPMT_PUBLIC         *publicArea,    // IN: public area
	   TPMT_SENSITIVE      *sensitive,     // IN: sensitive area (may be null)
	   TPM2B_NAME          *name,          // IN: object's name (may be null)
	   TPM_HANDLE           parentHandle,  // IN: handle of parent
	   BOOL                 skipChecks,    // IN: flag to indicate if it is OK to skip
	   //     consistency checks.
	   TPMI_DH_OBJECT      *handle         // OUT: object handle
	   );
TPM_RC
ObjectCreateHMACSequence(
			 TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
			 TPM_HANDLE       handle,        // IN: the handle associated with sequence
			 //     object
			 TPM2B_AUTH      *auth,          // IN: authValue
			 TPMI_DH_OBJECT  *newHandle      // OUT: HMAC sequence object handle
			 );
TPM_RC
ObjectCreateHashSequence(
			 TPMI_ALG_HASH    hashAlg,       // IN: hash algorithm
			 TPM2B_AUTH      *auth,          // IN: authValue
			 TPMI_DH_OBJECT  *newHandle      // OUT: sequence object handle
			 );
TPM_RC
ObjectCreateEventSequence(
			  TPM2B_AUTH      *auth,          // IN: authValue
			  TPMI_DH_OBJECT  *newHandle      // OUT: sequence object handle
			  );
void
ObjectTerminateEvent(
		     void
		     );
OBJECT *
ObjectContextLoad(
		  ANY_OBJECT_BUFFER   *object,        // IN: pointer to object structure in saved context
		  TPMI_DH_OBJECT      *handle         // OUT: object handle
		  );

void
ObjectFlush(
	    TPMI_DH_OBJECT   handle         // IN: handle to be freed
	    );
void
ObjectFlushHierarchy(
		     TPMI_RH_HIERARCHY    hierarchy      // IN: hierarchy to be flush
		     );
TPM_RC
ObjectLoadEvict(
		TPM_HANDLE      *handle,        // IN:OUT: evict object handle.  If success, it
		// will be replace by the loaded object handle
		COMMAND_INDEX    commandIndex   // IN: the command being processed
		);
void
ObjectComputeName(
		  TPMT_PUBLIC     *publicArea,    // IN: public area of an object
		  TPM2B_NAME      *name           // OUT: name of the object
		  );
void
ObjectComputeQualifiedName(
			   TPM2B_NAME      *parentQN,      // IN: parent's qualified name
			   TPM_ALG_ID       nameAlg,       // IN: name hash
			   TPM2B_NAME      *name,          // IN: name of the object
			   TPM2B_NAME      *qualifiedName  // OUT: qualified name of the object
			   );
BOOL
ObjectDataIsStorage(
		    TPMT_PUBLIC     *publicArea     // IN: public area of the object
		    );
BOOL
ObjectIsStorage(
		TPMI_DH_OBJECT   handle         // IN: object handle
		);
TPMI_YES_NO
ObjectCapGetLoaded(
		   TPMI_DH_OBJECT   handle,        // IN: start handle
		   UINT32           count,         // IN: count of returned handles
		   TPML_HANDLE     *handleList     // OUT: list of handle
		   );
UINT32
ObjectCapGetTransientAvail(
			   void
			   );

	   

#endif
