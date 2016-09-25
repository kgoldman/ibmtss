/********************************************************************************/
/*										*/
/*			    TSS and Application Utilities			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*		$Id: tssutils.c 729 2016-08-23 20:42:13Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015.						*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tsserror.h>

#define TSS_ALLOC_MAX  0x10000  /* 64k bytes */

extern int tssVerbose;
extern int tssVverbose;

/* TSS_Malloc() is a general purpose wrapper around malloc()
 */

TPM_RC TSS_Malloc(unsigned char **buffer, uint32_t size)
{
    TPM_RC          rc = 0;
    
    /* assertion test.  The coding style requires that all allocated pointers are initialized to
       NULL.  A non-NULL value indicates either a missing initialization or a pointer reuse (a
       memory leak). */
    if (rc == 0) {
        if (*buffer != NULL) {
            if (tssVerbose)
		printf("TSS_Malloc: Error (fatal), *buffer %p should be NULL before malloc\n",
		       *buffer);
            rc = TSS_RC_ALLOC_INPUT;
        }
    }
    /* verify that the size is not "too large" */
    if (rc == 0) {
        if (size > TSS_ALLOC_MAX) {
            if (tssVerbose) printf("TSS_Malloc: Error, size %u greater than maximum allowed\n",
				   size);
            rc = TSS_RC_MALLOC_SIZE;
        }       
    }
    /* verify that the size is not 0, this would be implementation defined and should never occur */
    if (rc == 0) {
        if (size == 0) {
            if (tssVerbose) printf("TSS_Malloc: Error (fatal), size is zero\n");
            rc = TSS_RC_MALLOC_SIZE;
        }       
    }
    if (rc == 0) {
        *buffer = malloc(size);
        if (*buffer == NULL) {
            if (tssVerbose) printf("TSS_Malloc: Error allocating %u bytes\n", size);
            rc = TSS_RC_OUT_OF_MEMORY;
        }
    }
    return rc;
}

/* TSS_Structure_Marshal() is a general purpose "marshal a structure" function.
   
   It marshals the structure using "marshalFunction", and returns the malloc'ed stream.

   FIXME use in TSS_File_WriteStructure
*/

TPM_RC TSS_Structure_Marshal(uint8_t		**buffer,	/* freed by caller */
			     uint16_t		*written,
			     void 		*structure,
			     MarshalFunction_t 	marshalFunction)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer1 = NULL;	/* for marshaling, moves pointer */

    /* marshal once to calculates the byte length */
    if (rc == 0) {
	*written = 0;
	rc = marshalFunction(structure, written, NULL, NULL);
    }
    if (rc == 0) {
	rc = TSS_Malloc(buffer, *written);
    }
    if (rc == 0) {
	buffer1 = *buffer;
	*written = 0;
	rc = marshalFunction(structure, written, &buffer1, NULL);
    }
    return rc;
}

/* TSS_File_Open() opens the 'filename' for 'mode'
 */

int TSS_File_Open(FILE **file,
		  const char *filename,
		  const char* mode)
{
    int 	rc = 0;
		    
    if (rc == 0) {
	*file = fopen(filename, mode);
	if (*file == NULL) {
	    if (tssVerbose) printf("TSS_File_Open: Error opening %s for %s, %s\n",
				   filename, mode, strerror(errno));
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    return rc;
}

/* TSS_File_ReadBinaryFile() reads 'filename'.  The results are put into 'data', which must be freed by
   the caller.  'length' indicates the number of bytes read. 
   
*/

TPM_RC TSS_File_ReadBinaryFile(unsigned char **data,     /* must be freed by caller */
			       size_t *length,
			       const char *filename) 
{
    int		rc = 0;
    long	lrc;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    *data = NULL;
    *length = 0;
    /* open the file */
    if (rc == 0) {
	rc = TSS_File_Open(&file, filename, "rb");				/* closed @1 */
    }
    /* determine the file length */
    if (rc == 0) {
	irc = fseek(file, 0L, SEEK_END);	/* seek to end of file */
	if (irc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error seeking to end of %s\n", filename);
	    rc = TSS_RC_FILE_SEEK;
	}
    }
    if (rc == 0) {
	lrc = ftell(file);			/* get position in the stream */
	if (lrc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error ftell'ing %s\n", filename);
	    rc = TSS_RC_FILE_FTELL;
	}
	else {
	    *length = (size_t)lrc;		/* save the length */
	}
    }
    if (rc == 0) {
	irc = fseek(file, 0L, SEEK_SET);	/* seek back to the beginning of the file */
	if (irc == -1L) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error seeking to beginning of %s\n",
				   filename);
	    rc = TSS_RC_FILE_SEEK;
	}
    }
    /* allocate a buffer for the actual data */
    if ((rc == 0) && (*length != 0)) {
	rc = TSS_Malloc(data, *length);
    }
    /* read the contents of the file into the data buffer */
    if ((rc == 0) && *length != 0) {
	src = fread(*data, 1, *length, file);
	if (src != *length) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error reading %s, %u bytes\n",
				   filename, (unsigned int)*length);
	    rc = TSS_RC_FILE_READ;
	}
    }
    if (file != NULL) {
	irc = fclose(file);		/* @1 */
	if (irc != 0) {
	    if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error closing %s\n",
				   filename);
	    rc = TSS_RC_FILE_CLOSE;
	}
    }
    if (rc != 0) {
	if (tssVerbose) printf("TSS_File_ReadBinaryFile: Error reading %s\n", filename);
	free(*data);
	data = NULL;
    }
    return rc;
}

/* TSS_File_WriteBinaryFile() writes 'data' of 'length' to 'filename'
 */

TPM_RC TSS_File_WriteBinaryFile(const unsigned char *data,
				size_t length,
				const char *filename) 
{
    long	rc = 0;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    /* open the file */
    if (rc == 0) {
	rc = TSS_File_Open(&file, filename, "wb");	/* closed @1 */
    }
    /* write the contents of the data buffer into the file */
    if (rc == 0) {
	src = fwrite(data, 1, length, file);
	if (src != length) {
	    if (tssVerbose) printf("TSS_File_WriteBinaryFile: Error writing %s\n",
				   filename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (file != NULL) {
	irc = fclose(file);		/* @1 */
	if (irc != 0) {
	    if (tssVerbose) printf("TSS_File_WriteBinaryFile: Error closing %s\n",
				   filename);
	    rc = TSS_RC_FILE_CLOSE;
	}
    }
    return rc;
}

/* TSS_File_ReadStructure() is a general purpose "read a structure" function.
   
   It reads the filename, and then unmarshals the structure using "unmarshalFunction".
*/

TPM_RC TSS_File_ReadStructure(void 			*structure,
			      UnmarshalFunction_t 	unmarshalFunction,
			      const char 		*filename)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer = NULL;		/* for the free */
    uint8_t	*buffer1 = NULL;	/* for unmarshaling */
    size_t 	length = 0;

    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* must be freed by caller */
				     &length,
				     filename);
    }
    if (rc == 0) {
	int32_t ilength = length;
	buffer1 = buffer;
	rc = unmarshalFunction(structure, &buffer1, &ilength);
    }
    free(buffer);
    return rc;
}

/* TSS_File_WriteStructure() is a general purpose "write a structure" function.
   
   It marshals the structure using "marshalFunction", and then writes it to filename.
*/

TPM_RC TSS_File_WriteStructure(void 			*structure,
			       MarshalFunction_t 	marshalFunction,
			       const char 		*filename)
{
    TPM_RC 	rc = 0;
    uint16_t	written = 0;;
    uint8_t	*buffer = NULL;		/* for the free */

    if (rc == 0) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   structure,
				   marshalFunction);
    }
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(buffer,
				      written,
				      filename); 
    }
    free(buffer);	/* @1 */
    return rc;
}

/* TSS_File_Read2B() reads 'filename' and copies the data to 'tpm2b', checking targetSize

 */

TPM_RC TSS_File_Read2B(TPM2B 		*tpm2b,
		       uint16_t 	targetSize,
		       const char 	*filename)
{
    TPM_RC 	rc = 0;
    uint8_t	*buffer = NULL;
    size_t 	length = 0;
    
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* must be freed by caller */
				     &length,
				     filename);
    }
    /* copy it into the TPM2B */
    if (rc == 0) {
	rc = TSS_TPM2B_Create(tpm2b, buffer, length, targetSize);
    }
    free(buffer);
    return rc;
}

/* FIXME need to add - ignore failure if does not exist */

TPM_RC TSS_File_DeleteFile(const char *filename) 
{
    TPM_RC 	rc = 0;
    int		irc;
    
    if (rc == 0) {
	irc = remove(filename);
	if (irc != 0) {
	    rc = TSS_RC_FILE_REMOVE;
	}
    }
    return rc;
}

/* TSS_TPM2B_Copy() copies source to target if the source fits the target size */

TPM_RC TSS_TPM2B_Copy(TPM2B *target, TPM2B *source, uint16_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (source->size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Copy: size %u greater than target %u\n",
				   source->size, targetSize);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	memmove(target->buffer, source->buffer, source->size);
	target->size = source->size;
    }
    return rc;
}

/* TSS_TPM2B_Append() appends the source TPM2B to the target TPM2B.
   
   It checks that the source fits the target size. The target size is the total size, not the size
   remaining.
*/

TPM_RC TSS_TPM2B_Append(TPM2B *target, TPM2B *source, uint16_t targetSize)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	if (target->size + source->size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Append: size %u greater than target %u\n",
				   target->size + source->size, targetSize);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	memmove(target->buffer + target->size, source->buffer, source->size);
	target->size += source->size;
    }
    return rc;
}

/* TSS_TPM2B_Create() copies the buffer of 'size' into target, checking targetSize */

TPM_RC TSS_TPM2B_Create(TPM2B *target, uint8_t *buffer, uint16_t size, uint16_t targetSize)
{
    TPM_RC rc = 0;
    
    if (rc == 0) {
	if (size > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_Create: size %u greater than target %u\n",
				   size, targetSize);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	target->size = size;
	memmove(target->buffer, buffer, size);
    }
    return rc;
}

/* TSS_TPM2B_CreateUint32() creates a TPM2B from a uint32_t, typically a permanent handle */

TPM_RC TSS_TPM2B_CreateUint32(TPM2B *target, uint32_t source, uint16_t targetSize)
{
    TPM_RC rc = 0;
    
    if (rc == 0) {
	if (sizeof(uint32_t) > targetSize) {
	    if (tssVerbose) printf("TSS_TPM2B_CreateUint32: size %u greater than target %u\n",
				   (unsigned int)sizeof(uint32_t), targetSize);	
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	uint32_t sourceNbo = htonl(source);
	memmove(target->buffer, (uint8_t *)&sourceNbo, sizeof(uint32_t));
	target->size = sizeof(uint32_t);
    }
    return rc;
}

/* TSS_TPM2B_StringCopy() copies a NUL terminated string (omiting the NUL) from source to target.
   
   It checks that the string will fit in targetSize.

   If source is NULL, creates a TPM2B of size 0.
*/

TPM_RC TSS_TPM2B_StringCopy(TPM2B *target, const char *source, uint16_t targetSize)
{
    TPM_RC rc = 0;
    size_t length;

    if (source != NULL) {
	if (rc == 0) {
	    length = strlen(source);
	    if (length > targetSize) {
		if (tssVerbose) printf("TSS_TPM2B_StringCopy: size %u greater than target %u\n",
				       (unsigned int)length, targetSize);	
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	if (rc == 0) {
	    target->size = length;
	    memcpy(target->buffer, source, length);
	}
    }
    else {
	target->size = 0;
    }
    return rc;
}

int TSS_TPM2B_Compare(TPM2B *expect, TPM2B *actual)
{
    int 	irc;
    int 	match = YES;

    if (match == YES) {
	if (expect->size != actual->size) {
	    match = NO;
	}
    }
    if (match == YES) {
	irc = memcmp(expect->buffer, actual->buffer, expect->size);
	if (irc != 0) {
	    match = NO;
	}
    }
    return match;
}

