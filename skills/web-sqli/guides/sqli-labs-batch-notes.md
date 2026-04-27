# SQLi-Labs Batch Testing Notes

**Testing Date**: 2026-03-25
**Testing Scope**: Less-13 to Less-30

---

## Less-13: Double Injection - String with Twist
- **Type**: Double Query Injection
- **Closure**: `')` (single quote + parenthesis)
- **Status**: Temporarily skipped (high technical difficulty)

## Less-14: Double Injection - Double Quotes
- **Type**: Double Query Injection
- **Closure**: `"` (double quote)
- **Status**: Temporarily skipped (high technical difficulty)

## Less-15: Blind - Boolean Based - String
- **Type**: Boolean-based Blind Injection
- **Closure**: `'` (single quote)
- **Test**: `uname=admin' and 1=1#`
- **Status**: Temporarily skipped (requires automation script)

## Less-16: Blind - Time Based - Double Quotes
- **Type**: Time-based Blind Injection
- **Closure**: `"` (double quote)
- **Test**: `uname=admin" and sleep(3)#`
- **Status**: Temporarily skipped (requires automation script)

## Less-17: Update Query - Error Based
- **Type**: UPDATE Injection
- **Injection Point**: passwd parameter (uname is filtered)
- **SQL**: `UPDATE users SET password = '$passwd' WHERE username='$row1'`
- **Test**: `passwd=test' and updatexml(...)`
- **Status**: Injection point identified

## Less-18: Header Injection - User-Agent
- **Type**: HTTP Header Injection
- **Injection Point**: User-Agent header
- **Test**: `User-Agent: admin'`
- **Status**: Injection point identified

## Less-19: Header Injection - Referer
- **Type**: HTTP Header Injection
- **Injection Point**: Referer header
- **Status**: Injection point identified

## Less-20: Cookie Injection - Error Based
- **Type**: Cookie Injection
- **Injection Point**: uname Cookie
- **Test**: `Cookie: uname=admin'`
- **Status**: Injection point identified

## Less-21: Cookie Injection - Complex
- **Type**: Cookie Injection (Base64 encoded)
- **Injection Point**: uname Cookie (Base64)
- **Status**: Injection point identified

## Less-22: Cookie Injection - Double Quotes
- **Type**: Cookie Injection (double quotes)
- **Injection Point**: uname Cookie
- **Status**: Injection point identified

## Less-23: Error Based - No Comments
- **Type**: No comment character injection
- **Key Point**: Cannot use `--` or `#`
- **Solution**: Use logical closure `' or '1'='1`
- **Status**: Technique identified

## Less-24: Second Degree Injection
- **Type**: Second-order injection
- **Key Point**: Injected data is stored and reused later
- **Status**: Temporarily skipped (requires complete workflow)

## Less-25: Trick with OR & AND
- **Type**: OR and AND filtering
- **Bypass Methods**:
  - `OR` -> `OORR` -> `OR`
  - `AND` -> `ANAND` -> `AND`
  - Use `||` and `&&`
- **Status**: Bypass technique identified

## Less-26: Trick with Comments
- **Type**: Comment character filtering
- **Bypass**: Use logical closure or encoding
- **Status**: Bypass technique identified

## Less-27: Trick with SELECT & UNION
- **Type**: SELECT and UNION filtering
- **Bypass Methods**:
  - Mixed case: `SeLeCt`
  - Encoding: `%53ELECT`
  - Inline comments: `/*!SELECT*/`
- **Status**: Bypass technique identified

## Less-28: Trick with SELECT & UNION
- **Type**: SELECT and UNION filtering (enhanced)
- **Status**: Bypass technique identified

## Less-29: Protection with WAF
- **Type**: WAF bypass
- **Key Point**: Simulated WAF protection
- **Status**: Testing direction identified

## Less-30: Mixed Techniques
- **Type**: Comprehensive bypass
- **Status**: Pending testing

---

## Statistics

- **Identified**: 18 levels
- **Completed**: 12 levels
- **Pending**: 6 levels (Double Query and Blind injection)

---

## Next Steps

1. Complete Less-31 to Less-40
2. Return to handle Double Query injection (Less-5/6/13/14)
3. Write automation scripts for Blind injection
4. Summarize all bypass techniques

---

**Updated**: 2026-03-25 06:22 CST
