lib_LTLIBRARIES = libibmtss.la
lib_LTLIBRARIES += libibmtssutils.la

# default TSS Library
libibmtss_la_SOURCES = tssfile.c tsscryptoh.c tsscrypto.c tssprintcmd.c

# TSS shared library object files
libibmtss_la_SOURCES += tss.c tssproperties.c tssmarshal.c tssauth.c tssutils.c tsssocket.c tssdev.c tsstransmit.c tssresponsecode.c tssccattributes.c tssprint.c Unmarshal.c CommandAttributeData.c

# TPM 2.0
# TSS share libarary object files
libibmtss_la_SOURCES += tss20.c tssauth20.c Commands.c
libibmtss_la_SOURCES += ntc2lib.c tssntc.c

# TSS utilities shared library source
libibmtss_la_SOURCES += cryptoutils.c ekutils.c imalib.c eventlib.c

libibmtss_la_SOURCES += tss12.c tssauth12.c tssmarshal12.c Unmarshal12.c Commands12.c tssccattributes12.c CommandAttributeData12.c

libibmtss_la_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX -fPIC -DTPM_TPM20

libibmtss_la_CFLAGS += -DTPM_TPM12
libibmtss_la_CFLAGS += -Wall -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wformat=2 -Wold-style-definition -Wno-self-assign -ggdb

#current[:revision[:age]]
#result: [current-age].age.revision
LIBIBMTSS_VERSION = 0:1:0
libibmtss_la_LDFLAGS = -version-info $(LIBIBMTSS_VERSION)
libibmtss_la_LIBADD =  $(IBMTPMTSS_SOURCES) $(OPENSSL_LIBS)

libibmtssutils_la_SOURCES = cryptoutils.c ekutils.c imalib.c eventlib.c
libibmtssutils_la_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX -fPIC -DTPM_TPM20
libibmtssutils_la_CFLAGS += -DTPM_TPM12
#current[:revision[:age]]
#result: [current-age].age.revision
libibmtssutils_la_LDFLAGS = -version-info $(LIBIBMTSS_VERSION)
libibmtssutils_la_LIBADD =  $(OPENSSL_LIBS)

noinst_HEADERS = CommandAttributes.h imalib.h tss12.h tssdev.h Commands12_fp.h ntc2lib.h tss20.h tssntc.h Commands_fp.h objecttemplates.h tssauth12.h tssproperties.h cryptoutils.h Platform.h tssauth.h tsssocket.h ekutils.h tssauth20.h tsstbsi.h eventlib.h tbs.h tssccattributes.h  ibmtss/tss.h ibmtss/tsscryptoh.h ibmtss/tsscrypto.h ibmtss/tsserror.h ibmtss/tssfile.h ibmtss/tssmarshal.h ibmtss/tssprint.h ibmtss/tssprintcmd.h ibmtss/tsstransmit.h ibmtss/tssresponsecode.h ibmtss/tssutils.h ibmtss/Unmarshal_fp.h ibmtss/Implementation.h

bin_PROGRAMS = activatecredential eventextend imaextend certify certifycreation changeeps changepps clear clearcontrol clockrateadjust clockset commit contextload contextsave create createloaded createprimary dictionaryattacklockreset dictionaryattackparameters duplicate eccparameters ecephemeral encryptdecrypt eventsequencecomplete evictcontrol flushcontext getcommandauditdigest getcapability getrandom gettestresult getsessionauditdigest gettime hashsequencestart hash hierarchycontrol hierarchychangeauth hmac hmacstart \
import importpem load loadexternal makecredential nvcertify nvchangeauth nvdefinespace nvextend nvglobalwritelock nvincrement nvread nvreadlock nvreadpublic nvsetbits nvundefinespace nvundefinespacespecial nvwrite nvwritelock objectchangeauth pcrallocate pcrevent pcrextend pcrread pcrreset policyauthorize policyauthvalue policycommandcode policycphash policynamehash policycountertimer policyduplicationselect policygetdigest policymaker policymakerpcr policyauthorizenv policynv policynvwritten \
policyor policypassword policypcr policyrestart policysigned policysecret policytemplate policyticket quote powerup readclock readpublic returncode rewrap rsadecrypt rsaencrypt sequenceupdate sequencecomplete setprimarypolicy shutdown sign startauthsession startup stirrandom unseal verifysignature zgen2phase signapp writeapp timepacket createek createekcert tpm2pem tpmpublic2eccpoint ntc2getconfig ntc2preconfig ntc2lockconfig

activatecredential_SOURCES = activatecredential.c
activatecredential_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
activatecredential_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

eventextend_SOURCES = eventextend.c
eventextend_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
eventextend_LDADD = libibmtssutils.la libibmtss.la

imaextend_SOURCES = imaextend.c
imaextend_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
imaextend_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

certify_SOURCES = certify.c
certify_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
certify_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

certifycreation_SOURCES = certifycreation.c
certifycreation_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
certifycreation_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

changeeps_SOURCES = changeeps.c
changeeps_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
changeeps_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

changepps_SOURCES = changepps.c
changepps_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
changepps_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

clear_SOURCES = clear.c
clear_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
clear_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

clearcontrol_SOURCES = clearcontrol.c
clearcontrol_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
clearcontrol_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

clockrateadjust_SOURCES = clockrateadjust.c
clockrateadjust_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
clockrateadjust_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

clockset_SOURCES = clockset.c
clockset_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
clockset_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

commit_SOURCES = commit.c
commit_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
commit_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

contextload_SOURCES = contextload.c
contextload_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
contextload_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

contextsave_SOURCES = contextsave.c
contextsave_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
contextsave_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

create_SOURCES = create.c objecttemplates.c
create_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
create_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

createloaded_SOURCES = createloaded.c objecttemplates.c
createloaded_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
createloaded_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

createprimary_SOURCES = createprimary.c objecttemplates.c
createprimary_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
createprimary_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

dictionaryattacklockreset_SOURCES = dictionaryattacklockreset.c
dictionaryattacklockreset_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
dictionaryattacklockreset_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

dictionaryattackparameters_SOURCES = dictionaryattackparameters.c
dictionaryattackparameters_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
dictionaryattackparameters_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

duplicate_SOURCES = duplicate.c
duplicate_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
duplicate_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

eccparameters_SOURCES = eccparameters.c
eccparameters_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
eccparameters_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

ecephemeral_SOURCES = ecephemeral.c
ecephemeral_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
ecephemeral_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

encryptdecrypt_SOURCES = encryptdecrypt.c
encryptdecrypt_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
encryptdecrypt_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

eventsequencecomplete_SOURCES = eventsequencecomplete.c
eventsequencecomplete_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
eventsequencecomplete_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

evictcontrol_SOURCES = evictcontrol.c
evictcontrol_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
evictcontrol_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

flushcontext_SOURCES = flushcontext.c
flushcontext_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
flushcontext_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

getcommandauditdigest_SOURCES = getcommandauditdigest.c
getcommandauditdigest_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
getcommandauditdigest_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

getcapability_SOURCES = getcapability.c
getcapability_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
getcapability_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

getrandom_SOURCES = getrandom.c
getrandom_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
getrandom_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

gettestresult_SOURCES = gettestresult.c
gettestresult_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
gettestresult_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

getsessionauditdigest_SOURCES = getsessionauditdigest.c
getsessionauditdigest_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
getsessionauditdigest_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

gettime_SOURCES = gettime.c
gettime_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
gettime_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hashsequencestart_SOURCES = hashsequencestart.c
hashsequencestart_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hashsequencestart_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hash_SOURCES = hash.c
hash_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hash_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hierarchycontrol_SOURCES = hierarchycontrol.c
hierarchycontrol_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hierarchycontrol_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hierarchychangeauth_SOURCES = hierarchychangeauth.c
hierarchychangeauth_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hierarchychangeauth_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hmac_SOURCES = hmac.c
hmac_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hmac_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

hmacstart_SOURCES = hmacstart.c
hmacstart_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
hmacstart_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

import_SOURCES = import.c
import_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
import_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

importpem_SOURCES = importpem.c objecttemplates.c
importpem_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
importpem_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

load_SOURCES = load.c
load_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
load_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

loadexternal_SOURCES = loadexternal.c
loadexternal_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
loadexternal_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

makecredential_SOURCES = makecredential.c
makecredential_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
makecredential_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvcertify_SOURCES = nvcertify.c
nvcertify_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvcertify_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvchangeauth_SOURCES = nvchangeauth.c
nvchangeauth_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvchangeauth_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvdefinespace_SOURCES = nvdefinespace.c
nvdefinespace_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvdefinespace_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvextend_SOURCES = nvextend.c
nvextend_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvextend_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvglobalwritelock_SOURCES = nvglobalwritelock.c
nvglobalwritelock_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvglobalwritelock_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvincrement_SOURCES = nvincrement.c
nvincrement_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvincrement_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvread_SOURCES = nvread.c
nvread_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvread_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvreadlock_SOURCES = nvreadlock.c
nvreadlock_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvreadlock_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvreadpublic_SOURCES = nvreadpublic.c
nvreadpublic_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvreadpublic_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvsetbits_SOURCES = nvsetbits.c
nvsetbits_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvsetbits_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvundefinespace_SOURCES = nvundefinespace.c
nvundefinespace_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvundefinespace_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvundefinespacespecial_SOURCES = nvundefinespacespecial.c
nvundefinespacespecial_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvundefinespacespecial_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvwrite_SOURCES = nvwrite.c
nvwrite_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvwrite_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

nvwritelock_SOURCES = nvwritelock.c
nvwritelock_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
nvwritelock_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

objectchangeauth_SOURCES = objectchangeauth.c
objectchangeauth_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
objectchangeauth_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

pcrallocate_SOURCES = pcrallocate.c
pcrallocate_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
pcrallocate_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

pcrevent_SOURCES = pcrevent.c
pcrevent_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
pcrevent_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

pcrextend_SOURCES = pcrextend.c
pcrextend_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
pcrextend_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

pcrread_SOURCES = pcrread.c
pcrread_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
pcrread_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

pcrreset_SOURCES = pcrreset.c
pcrreset_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
pcrreset_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyauthorize_SOURCES = policyauthorize.c
policyauthorize_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyauthorize_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyauthvalue_SOURCES = policyauthvalue.c
policyauthvalue_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyauthvalue_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policycommandcode_SOURCES = policycommandcode.c
policycommandcode_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policycommandcode_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policycphash_SOURCES = policycphash.c
policycphash_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policycphash_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policynamehash_SOURCES = policynamehash.c
policynamehash_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policynamehash_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policycountertimer_SOURCES = policycountertimer.c
policycountertimer_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policycountertimer_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyduplicationselect_SOURCES = policyduplicationselect.c
policyduplicationselect_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyduplicationselect_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policygetdigest_SOURCES = policygetdigest.c
policygetdigest_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policygetdigest_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policymaker_SOURCES = policymaker.c
policymaker_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policymaker_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policymakerpcr_SOURCES = policymakerpcr.c
policymakerpcr_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policymakerpcr_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyauthorizenv_SOURCES = policyauthorizenv.c
policyauthorizenv_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyauthorizenv_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policynv_SOURCES = policynv.c
policynv_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policynv_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policynvwritten_SOURCES = policynvwritten.c
policynvwritten_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policynvwritten_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyor_SOURCES = policyor.c
policyor_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyor_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policypassword_SOURCES = policypassword.c
policypassword_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policypassword_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policypcr_SOURCES = policypcr.c
policypcr_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policypcr_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyrestart_SOURCES = policyrestart.c
policyrestart_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyrestart_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policysigned_SOURCES = policysigned.c
policysigned_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policysigned_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policysecret_SOURCES = policysecret.c
policysecret_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policysecret_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policytemplate_SOURCES = policytemplate.c
policytemplate_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policytemplate_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

policyticket_SOURCES = policyticket.c
policyticket_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
policyticket_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

quote_SOURCES = quote.c
quote_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
quote_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

powerup_SOURCES = powerup.c
powerup_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
powerup_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

readclock_SOURCES = readclock.c
readclock_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
readclock_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

readpublic_SOURCES = readpublic.c
readpublic_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
readpublic_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

returncode_SOURCES = returncode.c
returncode_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
returncode_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

rewrap_SOURCES = rewrap.c
rewrap_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
rewrap_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

rsadecrypt_SOURCES = rsadecrypt.c
rsadecrypt_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
rsadecrypt_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

rsaencrypt_SOURCES = rsaencrypt.c
rsaencrypt_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
rsaencrypt_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

sequenceupdate_SOURCES = sequenceupdate.c
sequenceupdate_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
sequenceupdate_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

sequencecomplete_SOURCES = sequencecomplete.c
sequencecomplete_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
sequencecomplete_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

setprimarypolicy_SOURCES = setprimarypolicy.c
setprimarypolicy_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
setprimarypolicy_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

shutdown_SOURCES = shutdown.c
shutdown_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
shutdown_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

sign_SOURCES = sign.c
sign_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
sign_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

startauthsession_SOURCES = startauthsession.c
startauthsession_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
startauthsession_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

startup_SOURCES = startup.c
startup_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
startup_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

stirrandom_SOURCES = stirrandom.c
stirrandom_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
stirrandom_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

unseal_SOURCES = unseal.c
unseal_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
unseal_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

verifysignature_SOURCES = verifysignature.c
verifysignature_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
verifysignature_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

zgen2phase_SOURCES = zgen2phase.c
zgen2phase_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
zgen2phase_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

signapp_SOURCES = signapp.c
signapp_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
signapp_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

writeapp_SOURCES = writeapp.c
writeapp_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
writeapp_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

timepacket_SOURCES = timepacket.c
timepacket_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
timepacket_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

createek_SOURCES = createek.c
createek_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
createek_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

createekcert_SOURCES = createekcert.c
createekcert_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
createekcert_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

tpm2pem_SOURCES = tpm2pem.c
tpm2pem_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
tpm2pem_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

tpmpublic2eccpoint_SOURCES = tpmpublic2eccpoint.c
tpmpublic2eccpoint_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
tpmpublic2eccpoint_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

ntc2getconfig_SOURCES = ntc2getconfig.c
ntc2getconfig_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
ntc2getconfig_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

ntc2preconfig_SOURCES = ntc2preconfig.c
ntc2preconfig_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
ntc2preconfig_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la

ntc2lockconfig_SOURCES = ntc2lockconfig.c
ntc2lockconfig_CFLAGS = $(OPENSSL_CFLAGS) -DTPM_POSIX
ntc2lockconfig_LDADD = $(OPENSSL_LIBS) libibmtssutils.la libibmtss.la
