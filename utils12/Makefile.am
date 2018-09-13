transform=s&^&tss1&

if CONFIG_TPM12
lib_LTLIBRARIES = libibmtssutils12.la

libibmtssutils12_la_SOURCES = ekutils12.c
libibmtssutils12_la_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils
# current[:revision[:age]]
# result: [current-age].age.revision
libibmtssutils12_la_LDFLAGS = -version-info 0:1:0
libibmtssutils12_la_LIBADD =  $(OPENSSL_LIBS)

noinst_HEADERS = ekutils12.h

bin_PROGRAMS = activateidentity createendorsementkeypair createwrapkey extend flushspecific getcapability loadkey2 makeidentity nvdefinespace nvreadvalueauth nvreadvalue nvwritevalueauth nvwritevalue oiap osap ownerreadinternalpub ownersetdisable pcrread quote2 sign startup takeownership tpminit createekcert makeekblob eventextend imaextend

activateidentity_SOURCES = activateidentity.c
activateidentity_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
activateidentity_LDFLAGS = -L$(top_srcdir)/utils
activateidentity_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

createendorsementkeypair_SOURCES = createendorsementkeypair.c
createendorsementkeypair_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
createendorsementkeypair_LDFLAGS = -L$(top_srcdir)/utils
createendorsementkeypair_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

createwrapkey_SOURCES = createwrapkey.c
createwrapkey_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
createwrapkey_LDFLAGS = -L$(top_srcdir)/utils
createwrapkey_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

extend_SOURCES = extend.c
extend_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
extend_LDFLAGS = -L$(top_srcdir)/utils
extend_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

flushspecific_SOURCES = flushspecific.c
flushspecific_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
flushspecific_LDFLAGS = -L$(top_srcdir)/utils
flushspecific_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

getcapability_SOURCES = getcapability.c
getcapability_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
getcapability_LDFLAGS = -L$(top_srcdir)/utils
getcapability_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

loadkey2_SOURCES = loadkey2.c
loadkey2_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
loadkey2_LDFLAGS = -L$(top_srcdir)/utils
loadkey2_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

makeidentity_SOURCES = makeidentity.c
makeidentity_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
makeidentity_LDFLAGS = -L$(top_srcdir)/utils
makeidentity_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

nvdefinespace_SOURCES = nvdefinespace.c
nvdefinespace_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
nvdefinespace_LDFLAGS = -L$(top_srcdir)/utils
nvdefinespace_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

nvreadvalueauth_SOURCES = nvreadvalueauth.c
nvreadvalueauth_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
nvreadvalueauth_LDFLAGS = -L$(top_srcdir)/utils
nvreadvalueauth_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

nvreadvalue_SOURCES = nvreadvalue.c
nvreadvalue_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
nvreadvalue_LDFLAGS = -L$(top_srcdir)/utils
nvreadvalue_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

nvwritevalueauth_SOURCES = nvwritevalueauth.c
nvwritevalueauth_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
nvwritevalueauth_LDFLAGS = -L$(top_srcdir)/utils
nvwritevalueauth_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

nvwritevalue_SOURCES = nvwritevalue.c
nvwritevalue_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
nvwritevalue_LDFLAGS = -L$(top_srcdir)/utils
nvwritevalue_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

oiap_SOURCES = oiap.c
oiap_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
oiap_LDFLAGS = -L$(top_srcdir)/utils
oiap_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

osap_SOURCES = osap.c
osap_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
osap_LDFLAGS = -L$(top_srcdir)/utils
osap_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

ownerreadinternalpub_SOURCES = ownerreadinternalpub.c
ownerreadinternalpub_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
ownerreadinternalpub_LDFLAGS = -L$(top_srcdir)/utils
ownerreadinternalpub_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

ownersetdisable_SOURCES = ownersetdisable.c
ownersetdisable_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
ownersetdisable_LDFLAGS = -L$(top_srcdir)/utils
ownersetdisable_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

pcrread_SOURCES = pcrread.c
pcrread_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
pcrread_LDFLAGS = -L$(top_srcdir)/utils
pcrread_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

quote2_SOURCES = quote2.c
quote2_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
quote2_LDFLAGS = -L$(top_srcdir)/utils
quote2_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

sign_SOURCES = sign.c
sign_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
sign_LDFLAGS = -L$(top_srcdir)/utils
sign_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

startup_SOURCES = startup.c
startup_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
startup_LDFLAGS = -L$(top_srcdir)/utils
startup_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

takeownership_SOURCES = takeownership.c
takeownership_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
takeownership_LDFLAGS = -L$(top_srcdir)/utils
takeownership_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

tpminit_SOURCES = tpminit.c
tpminit_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
tpminit_LDFLAGS = -L$(top_srcdir)/utils
tpminit_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

createekcert_SOURCES = createekcert.c
createekcert_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
createekcert_LDFLAGS = -L$(top_srcdir)/utils
createekcert_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

makeekblob_SOURCES = makeekblob.c
makeekblob_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
makeekblob_LDFLAGS = -L$(top_srcdir)/utils
makeekblob_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

eventextend_SOURCES = eventextend.c
eventextend_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
eventextend_LDFLAGS = -L$(top_srcdir)/utils
eventextend_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto

imaextend_SOURCES = imaextend.c
imaextend_CFLAGS = $(OPENSSL_CFLAGS) -I$(top_srcdir)/utils -DTPM_TPM12
imaextend_LDFLAGS = -L$(top_srcdir)/utils
imaextend_LDADD =  libibmtssutils12.la ../utils/libibmtss.la -lcrypto
endif
