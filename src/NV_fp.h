/********************************************************************************/
/*										*/
/*			     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: NV_fp.h 55 2015-02-05 22:03:16Z kgoldman $			*/
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

#ifndef NV_FP_H
#define NV_FP_H

void
NvCheckState(void);
TPM_RC
NvIsAvailable(
	      void
	      );
BOOL
NvCommit(
	 void
	 );
void
NvInit(
       void
       );
void
NvReadReserved(
	       NV_RESERVE       type,          // IN: type of reserved data
	       void            *buffer         // OUT: buffer receives the data.
	       );
void
NvWriteReserved(
		NV_RESERVE       type,          // IN: type of reserved data
		void            *buffer         // IN: data buffer
		);
void
NvReadPersistent(
		 void
		 );
BOOL
NvIsPlatformPersistentHandle(
			     TPM_HANDLE       handle         // IN: handle
			     );
BOOL
NvIsOwnerPersistentHandle(
			  TPM_HANDLE       handle         // IN: handle
			  );
BOOL
NvPowerOn(
	  void
	  );
void
NvStateSave(
	    void
	    );
void
NvEntityStartup(
		STARTUP_TYPE     type           // IN: start up type
		);
BOOL
NvIsUndefinedIndex(
		   TPMI_RH_NV_INDEX     handle         // IN: handle
		   );
TPM_RC
NvIndexIsAccessible(
		    TPMI_RH_NV_INDEX     handle,        // IN: handle
		    COMMAND_INDEX        commandIndex   // IN: the command
		    );
TPM_RC
NvGetEvictObject(
		 TPM_HANDLE       handle,        // IN: handle
		 OBJECT          *object         // OUT: object data
		 );
void
NvGetIndexInfo(
	       TPMI_RH_NV_INDEX     handle,        // IN: handle
	       NV_INDEX            *nvIndex        // OUT: NV index structure
	       );
UINT64
NvInitialCounter(
		 void
		 );
void
NvGetIndexData(
	       TPMI_RH_NV_INDEX     handle,        // IN: handle
	       NV_INDEX            *nvIndex,       // IN: RAM image of index header
	       UINT32               offset,        // IN: offset of NV data
	       UINT16               size,          // IN: size of NV data
	       void                *data           // OUT: data buffer
	       );
void
NvGetIntIndexData(
		  TPMI_RH_NV_INDEX     handle,        // IN: handle
		  NV_INDEX            *nvIndex,       // IN: RAM image of NV Index header
		  UINT64              *data           // IN: UINT64 pointer for counter or bit
		  );
TPM_RC
NvWriteIndexInfo(
		 TPMI_RH_NV_INDEX     handle,        // IN: handle
		 NV_INDEX            *nvIndex        // IN: NV Index info to be written
		 );
TPM_RC
NvWriteIndexData(
		 TPMI_RH_NV_INDEX     handle,        // IN: handle
		 NV_INDEX            *nvIndex,       // IN: RAM copy of NV Index
		 UINT32               offset,        // IN: offset of NV data
		 UINT32               size,          // IN: size of NV data
		 void                *data           // OUT: data buffer
		 );
UINT16
NvGetName(
	  TPMI_RH_NV_INDEX     handle,        // IN: handle of the index
	  NAME                *name           // OUT: name of the index
	  );
TPM_RC
NvDefineIndex(
	      TPMS_NV_PUBLIC  *publicArea,    // IN: A template for an area to create.
	      TPM2B_AUTH      *authValue      // IN: The initial authorization value
	      );
TPM_RC
NvAddEvictObject(
		 TPMI_DH_OBJECT   evictHandle,   // IN: new evict handle
		 OBJECT          *object         // IN: object to be added
		 );
void
NvDeleteEntity(
	       TPM_HANDLE       handle         // IN: handle of entity to be deleted
	       );
void
NvFlushHierarchy(
		 TPMI_RH_HIERARCHY    hierarchy      // IN: hierarchy to be flushed.
		 );
void
NvSetGlobalLock(
		void
		);
TPMI_YES_NO
NvCapGetPersistent(
		   TPMI_DH_OBJECT   handle,        // IN: start handle
		   UINT32           count,         // IN: maximum number of returned handle
		   TPML_HANDLE     *handleList     // OUT: list of handle
		   );
TPMI_YES_NO
NvCapGetIndex(
	      TPMI_DH_OBJECT   handle,        // IN: start handle
	      UINT32           count,         // IN: maximum number of returned handle
	      TPML_HANDLE     *handleList     // OUT: list of handle
	      );
UINT32
NvCapGetIndexNumber(
		    void
		    );
UINT32
NvCapGetPersistentNumber(
			 void
			 );
UINT32
NvCapGetPersistentAvail(
			void
			);
UINT32
NvCapGetCounterNumber(
		      void
		      );
UINT32
NvCapGetCounterAvail(
		     void
		     );


#endif
