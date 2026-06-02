# Advanced Hashcat Rule-Based Attacks Guide

> Deep dive into hashcat's rule engine: built-in rule sets, custom rule authoring, combinator attacks, mask attacks, and performance optimization. Turn generic wordlists into targeted, high-success-rate attacks.

---

## Introduction

Dictionary attacks with raw wordlists are fast but limited — they only test exactly what is in the list. Real-world passwords are variations: "Summer2025!" instead of "summer", "P@ssw0rd" instead of "password". Hashcat's rule engine applies systematic transformations to each word in a wordlist, dramatically increasing coverage without proportionally increasing runtime. This guide covers the built-in rule sets, teaches you to write custom rules, and shows how to combine rules with masks and combinator attacks for maximum yield.

---

## Hands-on Exercise

### 1. Using Built-in Rule Sets

Hashcat ships with several rule files in the `rules/` directory.

```bash
# Best64 — fast, high-coverage rules (good first pass)
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# OneRuleToRuleThemStill — comprehensive, community-maintained
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemStill.rule

# Dive.rule — deep transformation set for stubborn hashes
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# List available rule files
ls /usr/share/hashcat/rules/
```

### 2. Hashcat Rule Syntax

Each rule is a single character function. Multiple functions can be chained in one rule.

| Rule | Function | Example |
|------|----------|---------|
| `l` | Lowercase all | Password -> password |
| `u` | Uppercase all | password -> PASSWORD |
| `c` | Capitalize first letter | password -> Password |
| `t` | Toggle case of all | password -> PASSWORD |
| `r` | Reverse | password -> drowssap |
| `d` | Duplicate | password -> passwordpassword |
| `$X` | Append character X | pass -> pass1 |
| `^X` | Prepend character X | pass -> 1pass |
| `sXY` | Replace X with Y | password -> p@ssword |
| `@X` | Purge character X | p@ssword -> pssword |
| `+N` | Truncate left by N | password -> ssword |
| `-N` | Truncate right by N | password -> passwo |

Example custom rules file:

```
# Append common years
$2 $0 $2 $5
$2 $0 $2 $4
# Capitalize and append !
c $!
# Prepend digit, capitalize
^1 c
^2 c
# Leet speak substitution
s a @ s s 5 s S $
```

Save as `custom.rules` and run:

```bash
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r custom.rules
```

### 3. Combinator Attacks

Combine two wordlists by concatenating every word from list A with every word from list B.

```bash
# Combinator attack with two wordlists
hashcat -m 1000 ntlm_hashes.txt -a 1 /usr/share/wordlists/colors.txt /usr/share/wordlists/animals.txt

# With a rule applied to the second wordlist
hashcat -m 1000 ntlm_hashes.txt -a 1 /usr/share/wordlists/colors.txt /usr/share/wordlists/animals.txt -j 'c' -k 'c $!'
```

### 4. Mask Attacks

When you know the password policy or structure, mask attacks are faster than rules.

```bash
# Company pattern: Season + Year + Symbol
hashcat -m 1000 ntlm_hashes.txt -a 3 ?u?l?l?l?l?l?d?d?d?d?s

# Common password structure: Capital word + 4 digits + symbol
hashcat -m 1000 ntlm_hashes.txt -a 3 ?u?l?l?l?l?l?l?d?d?d?d?s

# Using a mask file for multiple patterns
cat > masks.hcmask << 'EOF'
?u?l?l?l?l?l?d?d?d?d?s
?u?l?l?l?l?l?d?d?s
?l?l?l?l?l?l?d?d?d?d
?d?d?d?d?d?d?d?d?d?d?d?d
EOF
hashcat -m 1000 ntlm_hashes.txt masks.hcmask
```

Mask character sets:
- `?d` = digit, `?l` = lowercase, `?u` = uppercase, `?s` = special, `?a` = all printable

### 5. Rule Optimization

Stacking too many rules slows down attacks. Optimize for your target.

```bash
# Count candidates a rule set generates
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r custom.rules --stdout | wc -l

# Combine rules cautiously — two rule files multiply candidate count
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule -r custom.rules

# Benchmark a specific attack
hashcat -m 1000 -b
```

---

## References

- Hashcat Rule Engine Documentation: [https://hashcat.net/wiki/doku.php?id=rule_based_attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
- OneRuleToRuleThemStill: [https://github.com/NotSoSecure/password_cracking_rules](https://github.com/NotSoSecure/password_cracking_rules)
- Hashcat Mask Attack: [https://hashcat.net/wiki/doku.php?id=mask_attack](https://hashcat.net/wiki/doku.php?id=mask_attack)
- Hashcat Forum: [https://hashcat.net/forum/](https://hashcat.net/forum/)
