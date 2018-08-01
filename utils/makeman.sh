#!/bin/bash
#
#	$Id: makeman.sh 1290 2018-08-01 14:45:24Z kgoldman $
#
# script to make man pages
#
# Works with GNU help2man 1.47.6.  Is known not to work with older versions.

REV=`svn info -r HEAD | grep Revision | gawk '{ print $2 }'`
echo "For revision $REV"

mkdir -p man/man1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Activatecredential" ./activatecredential -o man/man1/tssactivatecredential.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Certify" ./certify -o man/man1/tsscertify.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_CertifyCreation" ./certifycreation -o man/man1/tsscertifycreation.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ChangeEPS" ./changeeps -o man/man1/tsschangeeps.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ChangePPS" ./changepps -o man/man1/tsschangepps.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Clear" ./clear -o man/man1/tssclear.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ClearControl" ./clearcontrol -o man/man1/tssclearcontrol.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ClockRateAdjust" ./clockrateadjust -o man/man1/tssclockrateadjust.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ClockSet" ./clockset -o man/man1/tssclockset.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Commit" ./commit -o man/man1/tsscommit.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ContextLoad" ./contextload -o man/man1/tsscontextload.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Contextsave" ./contextsave -o man/man1/tsscontextsave.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Create" ./create -o man/man1/tsscreate.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs createek demo" ./createek -o man/man1/tsscreateek.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs createekcert demo" ./createekcert -o man/man1/tsscreateekcert.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_CreateLoaded" ./createloaded -o man/man1/tsscreateloaded.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_CreatePrimary" ./createprimary -o man/man1/tsscreateprimary.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_DictionaryAttackLockReset" ./dictionaryattacklockreset -o man/man1/tssdictionaryattacklockreset.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_DictionaryAttackParameters" ./dictionaryattackparameters -o man/man1/tssdictionaryattackparameters.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Duplicate" ./duplicate -o man/man1/tssduplicate.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ECC_Parameters" ./eccparameters -o man/man1/tsseccparameters.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_EC_Ephemeral" ./ecephemeral -o man/man1/tssecephemeral.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_EncryptDecrypt" ./encryptdecrypt -o man/man1/tssencryptdecrypt.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_EventExtend" ./eventextend -o man/man1/tsseventextend.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_EventSequenceComplete" ./eventsequencecomplete -o man/man1/tsseventsequencecomplete.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_EvictControl" ./evictcontrol -o man/man1/tssevictcontrol.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_FlushContext" ./flushcontext -o man/man1/tssflushcontext.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetCapability" ./getcapability -o man/man1/tssgetcapability.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetCommandAuditDigest" ./getcommandauditdigest -o man/man1/tssgetcommandauditdigest.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetRandom" ./getrandom -o man/man1/tssgetrandom.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetTestResult" ./gettestresult -o man/man1/tssgettestresult.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetSessionAuditDigest" ./getsessionauditdigest -o man/man1/tssgetsessionauditdigest.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_GetTime" ./gettime -o man/man1/tssgettime.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Hash" ./hash -o man/man1/tsshash.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_HashSequenceStart" ./hashsequencestart -o man/man1/tsshashsequencestart.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_HierarchyChangeauth" ./hierarchychangeauth -o man/man1/tsshierarchychangeauth.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_HierarchyControl" ./hierarchycontrol -o man/man1/tsshierarchycontrol.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Hmac" ./hmac -o man/man1/tsshmac.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_HmacStart" ./hmacstart -o man/man1/tsshmacstart.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs imaextend simulation" ./imaextend -o man/man1/tssimaextend.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Import" ./import -o man/man1/tssimport.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Import with PEM input" ./importpem -o man/man1/tssimportpem.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Load" ./load -o man/man1/tssload.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_LoadExternal" ./loadexternal -o man/man1/tssloadexternal.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_MakeCredential" ./makecredential -o man/man1/tssmakecredential.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Ntc2GetConfig" ./ntc2getconfig -o man/man1/tssntc2getconfig.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Ntc2LockConfig" ./ntc2lockconfig -o man/man1/tssntc2lockconfig.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Ntc2Preconfig" ./ntc2preconfig -o man/man1/tssntc2preconfig.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Certify" ./nvcertify -o man/man1/tssnvcertify.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_ChangeAuth" ./nvchangeauth -o man/man1/tssnvchangeauth.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_DefineSpace" ./nvdefinespace -o man/man1/tssnvdefinespace.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Extend" ./nvextend -o man/man1/tssnvextend.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_GlobalWriteLock" ./nvglobalwritelock -o man/man1/tssnvglobalwritelock.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Increment" ./nvincrement -o man/man1/tssnvincrement.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Read" ./nvread -o man/man1/tssnvread.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_ReadLock" ./nvreadlock -o man/man1/tssnvreadlock.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_ReadPublic" ./nvreadpublic -o man/man1/tssnvreadpublic.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_SetBits" ./nvsetbits -o man/man1/tssnvsetbits.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_UndefineSpace" ./nvundefinespace -o man/man1/tssnvundefinespace.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_UndefineSpaceSpecial" ./nvundefinespacespecial -o man/man1/tssnvundefinespacespecial.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Write" ./nvwrite -o man/man1/tssnvwrite.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_NV_Writelock" ./nvwritelock -o man/man1/tssnvwritelock.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Objectchangeauth" ./objectchangeauth -o man/man1/tssobjectchangeauth.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PCR_Allocate" ./pcrallocate -o man/man1/tsspcrallocate.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PCR_Event" ./pcrevent -o man/man1/tsspcrevent.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PCR_Extend" ./pcrextend -o man/man1/tsspcrextend.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PCR_Read" ./pcrread -o man/man1/tsspcrread.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PCR_Reset" ./pcrreset -o man/man1/tsspcrreset.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyAuthorize" ./policyauthorize -o man/man1/tsspolicyauthorize.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyAuthorizeNV" ./policyauthorizenv -o man/man1/tsspolicyauthorizenv.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyAuthValue" ./policyauthvalue -o man/man1/tsspolicyauthvalue.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyCommandCode" ./policycommandcode -o man/man1/tsspolicycommandcode.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyCounterTimer" ./policycountertimer -o man/man1/tsspolicycountertimer.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyCpHash" ./policycphash -o man/man1/tsspolicycphash.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyDuplicationSelect" ./policyduplicationselect -o man/man1/tsspolicyduplicationselect.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyGetDigest" ./policygetdigest -o man/man1/tsspolicygetdigest.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs policymaker utility" ./policymaker -o man/man1/tsspolicymaker.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs policymakerpcr utility" ./policymakerpcr -o man/man1/tsspolicymakerpcr.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyNv" ./policynv -o man/man1/tsspolicynv.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyNvWritten" ./policynvwritten -o man/man1/tsspolicynvwritten.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyOR" ./policyor -o man/man1/tsspolicyor.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyPassword" ./policypassword -o man/man1/tsspolicypassword.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyPCR" ./policypcr -o man/man1/tsspolicypcr.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyRestart" ./policyrestart -o man/man1/tsspolicyrestart.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicySecret" ./policysecret -o man/man1/tsspolicysecret.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicySigned" ./policysigned -o man/man1/tsspolicysigned.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyTemplate" ./policytemplate -o man/man1/tsspolicytemplate.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_PolicyTicket" ./policyticket -o man/man1/tsspolicyticket.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs powerup simulation" ./powerup -o man/man1/tsspowerup.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Quote" ./quote -o man/man1/tssquote.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ReadClock" ./readclock -o man/man1/tssreadclock.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ReadPublic" ./readpublic -o man/man1/tssreadpublic.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs returncode parser" ./returncode -o man/man1/tssreturncode.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Rewrap" ./rewrap -o man/man1/tssrewrap.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_RsaDecrypt" ./rsadecrypt -o man/man1/tssrsadecrypt.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_RsaEncrypt" ./rsaencrypt -o man/man1/tssrsaencrypt.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_SequenceComplete" ./sequencecomplete -o man/man1/tsssequencecomplete.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_SequenceUpdate" ./sequenceupdate -o man/man1/tsssequenceupdate.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_SetPrimarypolicy" ./setprimarypolicy -o man/man1/tsssetprimarypolicy.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Shutdown" ./shutdown -o man/man1/tssshutdown.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Sign" ./sign -o man/man1/tsssign.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Signapp" ./signapp -o man/man1/tsssignapp.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_StartAuthSession" ./startauthsession -o man/man1/tssstartauthsession.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Startup" ./startup -o man/man1/tssstartup.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_StirRandom" ./stirrandom -o man/man1/tssstirrandom.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs timepacket profiler" ./timepacket -o man/man1/tsstimepacket.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs tpm2pem demo" ./tpm2pem -o man/man1/tsstpm2pem.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs tpmpublic2eccpoint demo" ./tpmpublic2eccpoint -o man/man1/tsstpmpublic2eccpoint.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_Unseal" ./unseal -o man/man1/tssunseal.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_VerifySignature" ./verifysignature -o man/man1/tssverifysignature.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs writeapp demo" ./writeapp -o man/man1/tsswriteapp.1
help2man --help-option=-h --version-string="${REV}" -N -n "Runs TPM2_ZGen_2Phase" ./zgen2phase -o man/man1/tsszgen2phase.1
