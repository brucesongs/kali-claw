# Cryptographic Attacks Test Cases

> This file is a companion to `SKILL.md`, containing structured test cases grouped by attack type with severity ratings and verification criteria.

---

## Statistics

| Category | Count | Severity Range |
|------|------|-----------|
| A. Cryptographic Detection | 2 | MEDIUM - HIGH |
| B. Hash Cracking | 2 | HIGH - CRITICAL |
| C. Protocol Attacks | 2 | HIGH - CRITICAL |
| D. JWT Attacks | 2 | HIGH - CRITICAL |
| E. Advanced Techniques | 3 | HIGH - CRITICAL |
| **Total** | **11** | **MEDIUM - CRITICAL** |

---

## A. Cryptographic Detection

### TC-CRYPTO-001: SSL/TLS Weak Protocol Version Detection

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-001 |
| **Name** | SSL/TLS Weak Protocol Version Detection |
| **Severity** | HIGH |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | Objective Web serviceopen HTTPS (443); already install testssl.sh, sslscan, openssl |
| **Test Steps** | 1. Run `testssl.sh --protocols target.com`<br>2. Use `sslscan target.com` crossVerify<br>3. manual `openssl s_client -connect target:443 -tls1` Confirm<br>4. Recordall supports protocolversion |
| **Expected Results (vulnerability)** | serviceendsupports SSLv3、TLS 1.0 or TLS 1.1 |
| **Expected Results (security )** | onlysupports TLS 1.2 and TLS 1.3 |
| **Remediation** | disableall lowat TLS 1.2 protocolversion; Configure `SSLProtocol -all +TLSv1.2 +TLSv1.3` |

### TC-CRYPTO-002: Weak Cipher Suite & Key Length Detection

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-002 |
| **Name** | Weak Cipher Suite & Key Length Detection |
| **Severity** | MEDIUM |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | Objective Web serviceopen HTTPS; already install testssl.sh |
| **Test Steps** | 1. Run `testssl.sh --ciphers target.com`<br>2. Checkiswhethersupports RC4/DES/3DES/NULL/EXPORT passwordsetpiece<br>3. Checkcertificatekeylengthdegree (RSA < 2048 asweak)<br>4. Checksignaturealgorithm (MD5/SHA1 signaturecertificateasweak) |
| **Expected Results (vulnerability)** | exists RC4/DES/3DES/NULL passwordsetpiece; RSA key < 2048 bit; certificateUse SHA1 signature |
| **Expected Results (security )** | onlysupports AEAD passwordsetpiece (AES-GCM/ChaCha20-Poly1305); RSA >= 2048 or ECDSA P-256+ |
| **Remediation** | disableall weakpasswordsetpiece; Use TLS 1.3 priority; certificatekeyat least RSA 2048 or ECDSA |

---

## B. Hash Cracking

### TC-CRYPTO-003: Hash Type Identification & Weak Hash Detection

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-003 |
| **Name** | Hash Type Identification & Weak Hash Detection |
| **Severity** | HIGH |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | ObtainObjectivesystemstorage passwordhashsamplethis; already install hash-identifier, hashcat |
| **Test Steps** | 1. Use `hash-identifier` or `hashcat --identify` Identifyhashtype<br>2. judgeiswhetherasweakhashalgorithm (MD5/SHA1 nosalt)<br>3. such as resultasweakhash，Attempt `hashcat -a 0 -m <MODE> hashes.txt rockyou.txt` dictionarycrack<br>4. such as dictionaryfailure，Attemptruleattack `hashcat -a 0 -m <MODE> hashes.txt rockyou.txt -r best64.rule`<br>5. Recordcracksuccessrateand耗when |
| **Expected Results (vulnerability)** | hashUse MD5/SHA1 andnosalt; dictionary attackcan crack >30% hash |
| **Expected Results (security )** | Use bcrypt/argon2id/scrypt; hassalt; dictionary attackcrackrate <1% |
| **Remediation** | 迁moveto bcrypt (cost >= 12) or argon2id; ensureeachhashindependentsaltValue |

### TC-CRYPTO-004: Salted vs. Unsalted Hash Cracking Comparison

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-004 |
| **Name** | Salted vs. Unsalted Hash Cracking Comparison |
| **Severity** | CRITICAL |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | Obtainsameausergroupbody addsaltandnosalthasheacha份; already install hashcat |
| **Test Steps** | 1. fornosalt MD5 hashExecute `hashcat -a 0 -m 0 unsalted.txt rockyou.txt`<br>2. foraddsalt MD5 hashExecute `hashcat -a 0 -m 10 salted.txt rockyou.txt`<br>3. Record两er crackspeeddegreeandsuccessrate<br>4. Attemptrainbow tableattacknosalthash (Use rtgen/rtsort)<br>5. Compareaddsaltafterrainbow tableattackiswhether失effect |
| **Expected Results (vulnerability)** | nosalthashcan byquick crackandrainbow tableeffective; addsalthashcrack成thissignificantincrease |
| **Expected Results (security )** | all hashallUseindependentsaltValue; rainbow tableattacknotcan row |
| **Remediation** | all passwordhashmustUseindependentrandomsaltValue (>=16 bytes); priorityUse bcrypt/argon2id |

---

## C. Protocol Attacks

### TC-CRYPTO-005: Padding Oracle Attack Verification

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-005 |
| **Name** | Padding Oracle Attack Verification |
| **Severity** | CRITICAL |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | ObjectiveapplicationUse CBC modeencryption (Cookie/parameter); serviceendforpaddingerrorreturnnotsameresponse; already install padbuster |
| **Test Steps** | 1. captureaencryptionparametersamplethis (such as Cookie in encryptionValue)<br>2. tampermostafterbyteandsend，Observeserviceendresponsedifference<br>3. Confirm Oracle exists (paddingerror = HTTP 500/notsameerrormessage)<br>4. Run `padbuster URL ENC 8 -encoding 0` decryptiondata<br>5. Run `padbuster URL ENC 8 -encoding 0 -plaintext "admin=true"` encryptionarbitrarydata |
| **Expected Results (vulnerability)** | Oracle exists; can 逐bytedecryptionciphertext; can encryptionarbitraryplaintextandobtaincombinemethodciphertext |
| **Expected Results (security )** | serviceendnotleakagepaddingeffectiveityinformation; orUse AEAD mode (GCM) |
| **Remediation** | Use AES-GCM/ChaCha20-Poly1305 alternative CBC; unifiederrormessagenotleakagedecryption细section; 先Verify HMAC 再decryption |

### TC-CRYPTO-006: Hash Length Extension Attack Verification

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-006 |
| **Name** | Hash Length Extension Attack Verification |
| **Severity** | HIGH |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | ObjectiveUse H(secret \|\| message) 形style MAC; attackercan ObtainhashValueandmessage; already install htlea |
| **Test Steps** | 1. AnalyzeObjective MAC Constructmethod (iswhetheras H(key \|\| data))<br>2. Obtaincombinemethodrequest hashValueandmessagelengthdegree<br>3. Use `htlea.py sha1 <hash> <length> "&admin=true"` Generateextensionhash<br>4. Constructcontainsextensiondata requestsendtoserviceend<br>5. Observeserviceendiswhetheracceptforgery hashValue |
| **Expected Results (vulnerability)** | serviceendaccept Length Extension forgery hashValue; attackercan 追addarbitrarydata |
| **Expected Results (security )** | serviceendUse HMAC; Length Extension forgery hashbydeny |
| **Remediation** | will MAC Constructfrom H(key \|\| msg) replaceas HMAC(key, msg); orUse SHA-3 (notaffected Length Extension impact) |

---

## D. JWT Attacks

### TC-CRYPTO-007: JWT alg:none Signature Bypass

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-007 |
| **Name** | JWT alg:none Signature Bypass |
| **Severity** | CRITICAL |
| **OWASP** | A04:2021 - Cryptographic Failures / A07:2021 - Identification and Authentication Failures |
| **Prerequisites** | ObjectiveUse JWT performauthentication; can Obtaincombinemethod JWT Token; already install jwt_tool |
| **Test Steps** | 1. Obtaincombinemethod JWT Token<br>2. decode Token viewcurrentalgorithmand Payload: `python3 jwt_tool.py <TOKEN> -T`<br>3. Use alg:none bypass: `python3 jwt_tool.py <TOKEN> -X a`<br>4. Attemptmultiplekind alg changebody: `none`/`None`/`NONE`/`nOnE`<br>5. Useforgery Token accessaffectedprotectresource<br>6. modify Payload in role/user Fieldas admin |
| **Expected Results (vulnerability)** | serviceendaccept alg:none Token andnotVerifysignature; attackercan forgeryarbitraryidentity |
| **Expected Results (security )** | serviceenddeny alg:none Token; return 401/403 |
| **Remediation** | serviceendforcealgorithmwhitelist (onlyallows RS256/ES256); deny alg as none Token; Use成熟 JWT library |

### TC-CRYPTO-008: JWT Algorithm Confusion Attack

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-008 |
| **Name** | JWT Algorithm Confusion (RS256 -> HS256) |
| **Severity** | CRITICAL |
| **OWASP** | A04:2021 - Cryptographic Failures / A07:2021 - Identification and Authentication Failures |
| **Prerequisites** | ObjectiveUse RS256 signature JWT; can Obtain RSA public key (JWKS endpointorcertificate); already install jwt_tool |
| **Test Steps** | 1. from `/.well-known/jwks.json` orcertificateExtract RSA public key<br>2. savepublic keyto `public_key.pem`<br>3. Use Algorithm Confusion attack: `python3 jwt_tool.py <TOKEN> -I -at HS256 -pc role -pv admin -k public_key.pem`<br>4. Useforgery Token accessaffectedprotectresource<br>5. such as failure，Attempt JWT keybrute force: `hashcat -m 16500 jwt_hash.txt rockyou.txt` |
| **Expected Results (vulnerability)** | serviceendusepublic keyVerify HMAC signature -> Verifythrough; attackercan forgeryarbitraryidentity |
| **Expected Results (security )** | serviceendstrictly zonepart RS256 and HS256 Verifylogic; denyobfuscation |
| **Remediation** | Verifywhen 显stylespecify预periodalgorithm (notfrom Token header read alg); Usetypesecurity JWT library; public keyand HMAC keypart开storage |

---

## E. Advanced Techniques

### TC-CRYPTO-009: ECB Mode Detection & Byte-at-a-time Attack

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-009 |
| **Name** | ECB Mode Detection & Byte-at-a-time Attack |
| **Severity** | HIGH |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | ObjectiveapplicationUseencryptionstorageuserdata; attackercan controlpartialencryptioninput; can Observeencryptionafter ciphertext |
| **Test Steps** | 1. commitrepeatplaintext (such as 32 A: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)<br>2. Observeciphertextiswhetheroutputnowrepeatblock -> Confirm ECB mode<br>3. confirmblocksize (typically 16 byte): 逐渐increaseinputlengthdegree直tociphertextincreaseablock<br>4. Execute Byte-at-a-time attack: 逐bytecontrolbefore缀，Compareciphertextdictionary<br>5. recovercomplexnot knowencryptiondata |
| **Expected Results (vulnerability)** | ciphertextoutputnowrepeatblock (ECB Confirm); can 逐byterecovercomplexencryptiondata |
| **Expected Results (security )** | identicalplaintextgeneratenotsameciphertext (Use CBC/GCM/CTR + random IV); notexistsrepeatblock |
| **Remediation** | Use AES-CBC (random IV) or AES-GCM; 绝notinnewsysteminUse ECB mode |

### TC-CRYPTO-010: RSA Weak Parameter Attack

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-010 |
| **Name** | RSA Weak Parameter Attack |
| **Severity** | HIGH |
| **OWASP** | A04:2021 - Cryptographic Failures |
| **Prerequisites** | Obtain RSA public key (N, e); N assmallmodenumberor e assmallpointnumber; already install RsaCtfTool |
| **Test Steps** | 1. Extract RSA public keyparameter: `openssl rsa -pubin -in key.pem -text -noout`<br>2. Checkmodenumber N lengthdegree (< 1024 bitasweak)<br>3. Checkpublic keypointnumber e (=3 can canexistssmallpointnumberattack)<br>4. Run `python3 RsaCtfTool.py -n <N> -e <e> --private` Attemptrecovercomplexprivate key<br>5. such as private keyrecovercomplexsuccess，decryptionObjectiveciphertext |
| **Expected Results (vulnerability)** | RSA modenumbercan bypartsolve; private keycan byrecovercomplex; ciphertextcan bydecryption |
| **Expected Results (security )** | RSA modenumber >= 2048 bit; Use OAEP padding; e = 65537; nomethodincombinereasonwhen intervalinnerpartsolve |
| **Remediation** | Use RSA-2048 ormorelargekey; Use RSA-OAEP andnon PKCS#1 v1.5; priorityconsider ECC (P-256) |

### TC-CRYPTO-011: SSL/TLS Known Vulnerability Detection

| Field | Value |
|------|-----|
| **ID** | TC-CRYPTO-011 |
| **Name** | SSL/TLS Known Vulnerability Detection (Heartbleed/POODLE/Logjam) |
| **Severity** | CRITICAL |
| **OWASP** | A04:2021 - Cryptographic Failures / A05:2021 - Security Misconfiguration |
| **Prerequisites** | Objective Web serviceopen HTTPS; already install testssl.sh, nmap |
| **Test Steps** | 1. Run `testssl.sh --vulnerabilities target.com` comprehensive Scan<br>2. 逐itemCheck: Heartbleed (CVE-2014-0160)、POODLE (CVE-2014-3566)、Logjam (CVE-2015-4000)<br>3. Check DROWN (CVE-2016-0800): SSLv2 iswhetherenable<br>4. Check ROBOT (Return Of Bleichenbacher's Oracle Threat): `testssl.sh -B target.com`<br>5. Use nmap supplement: `nmap --script ssl-heartbleed,ssl-poodle,ssl-dh-params -p 443 target.com` |
| **Expected Results (vulnerability)** | exists Heartbleed (can leakagememory)、POODLE (can decryption CBC)、Logjam (can downgradelevel DH) etc.already knowvulnerability |
| **Expected Results (security )** | all already know TLS vulnerability detectionresultas阴ity; OpenSSL versionnoalready know CVE |
| **Remediation** | upgradelevel OpenSSL tolatest稳定版; disable SSLv2/SSLv3; disableweak DH parameter (< 2048); enable TLS 1.3 |
