# SQLi-Labs Complete Learning Roadmap

**Start Date**: 2026-03-24
**Last Updated**: 2026-03-25 06:25 CST
**Overall Progress**: 12/65 (18.5%)

---

## Level Classification

### Stage 1: Basic GET Injection (Less-1 to Less-10)

#### Completed (4/10)
- **Less-1**: GET - Error based - Single quotes - String
- **Less-2**: GET - Error based - Integer based
- **Less-3**: GET - Error based - Single quotes with twist
- **Less-4**: GET - Error based - Double Quotes

#### Temporarily Skipped (3/10)
- **Less-5**: Double Query - Single Quotes - String
- **Less-6**: Double Query - Double Quotes - String
- **Less-7**: Dump into Outfile

#### Completed (3/10)
- **Less-8**: Blind - Boolean Based - Single Quotes
- **Less-9**: Blind - Time Based - Single Quotes
- **Less-10**: Blind - Time Based - Double Quotes

### Stage 2: POST Injection (Less-11 to Less-22)

#### Completed (2/12)
- **Less-11**: POST - Error Based - String
- **Less-12**: POST - Error Based - Double Quotes

#### Temporarily Skipped (4/12)
- **Less-13**: Double Injection - String with Twist
- **Less-14**: Double Injection - Double Quotes
- **Less-15**: Blind - Boolean Based
- **Less-16**: Blind - Time Based

#### Identified (6/12)
- **Less-17**: Update Query - Error Based
- **Less-18**: Header Injection - User-Agent
- **Less-19**: Header Injection - Referer
- **Less-20**: Cookie Injection - Error Based
- **Less-21**: Cookie Injection - Complex
- **Less-22**: Cookie Injection - Double Quotes

### Stage 3: Filter Bypass (Less-23 to Less-37)

#### Identified (8/15)
- **Less-23**: Error Based - No Comments
- **Less-24**: Second Degree Injection
- **Less-25**: Trick with OR & AND
- **Less-26**: Trick with Comments
- **Less-27**: Trick with SELECT & UNION
- **Less-28**: Trick with SELECT & UNION
- **Less-29**: Protection with WAF
- **Less-30**: Mixed Techniques

#### To Learn (7/15)
- **Less-31**: FUN with WAF
- **Less-32**: Bypass addslashes()
- **Less-33**: Bypass addslashes()
- **Less-34**: Bypass Add SLASHES
- **Less-35**: Why care for addslashes()
- **Less-36**: Bypass MySQL Real Escape String
- **Less-37**: MySQL_real_escape_string

### Stage 4: Stacked Queries (Less-38 to Less-53)

#### To Learn (16/16)
- **Less-38**: Stacked Query
- **Less-39**: Stacked Query Integer type
- **Less-40**: Stacked Query String type Blind
- **Less-41**: Stacked Query Integer type blind
- **Less-42**: Stacked Query error based
- **Less-43**: Stacked Query
- **Less-44**: Stacked Query blind
- **Less-45**: Stacked Query Blind based twist
- **Less-46**: ORDER BY-Error-Numeric
- **Less-47**: ORDER BY Clause-Error-Single quote
- **Less-48**: ORDER BY Clause Blind based
- **Less-49**: ORDER BY Clause Blind based
- **Less-50**: ORDER BY Clause Blind based
- **Less-51**: ORDER BY Clause Blind based
- **Less-52**: ORDER BY Clause Blind based
- **Less-53**: ORDER BY Clause Blind based

### Stage 5: Challenge Levels (Less-54 to Less-65)

#### To Learn (12/12)
- **Less-54**: Challenge-1
- **Less-55**: Challenge-2
- **Less-56**: Challenge-3
- **Less-57**: Challenge-4
- **Less-58**: Challenge-5
- **Less-59**: Challenge-6
- **Less-60**: Challenge-7
- **Less-61**: Challenge-8
- **Less-62**: Challenge-9
- **Less-63**: Challenge-10
- **Less-64**: Challenge-11
- **Less-65**: Challenge-12

---

## Learning Statistics

### Progress Overview
- **Completed**: 12 levels (18.5%)
- **Identified**: 14 levels (21.5%)
- **To Learn**: 33 levels (50.8%)
- **Skipped**: 6 levels (9.2%)

### Technical Proficiency
- **UNION Injection**: Mastered
- **POST Injection**: Mastered
- **Blind Injection**: Basic mastery
- **Header Injection**: Identifying
- **Cookie Injection**: Identifying
- **Filter Bypass**: Learning
- **Stacked Query**: Not started
- **ORDER BY Injection**: Not started

---

## Learning Strategy

### Priority P0 (Complete Immediately)
1. Complete Less-17 to Less-22 (UPDATE/Header/Cookie)
2. Complete Less-31 to Less-37 (addslashes bypass)

### Priority P1 (Complete This Week)
1. Return to handle Double Query injection (Less-5/6/13/14)
2. Write automation scripts for Blind injection
3. Complete Less-38 to Less-45 (Stacked Query)

### Priority P2 (Complete Next Week)
1. Complete Less-46 to Less-53 (ORDER BY injection)
2. Complete Challenge levels (Less-54 to Less-65)

### Priority P3 (Long-term Goals)
1. Summarize all bypass techniques
2. Build an automated testing tool library
3. Compile best practices and tips

---

## Tools and Resources

### Configured Tools
- sqlmap 1.10.2
- curl (manual testing)
- MariaDB 11.8.6
- PHP 8.4.16

### Learning Resources
- SQLi-Labs source code: `/var/www/html/sqli-labs/`
- Progress record: `/home/parallels/.openclaw/workspace/memory/sqli-labs-progress.md`
- Batch notes: `/home/parallels/.openclaw/workspace/memory/sqli-labs-batch-notes.md`

---

## Key Technical Points Summary

### Closure Types Summary
- `'` - Single quote
- `"` - Double quote
- `')` - Single quote + parenthesis
- `")` - Double quote + parenthesis
- `'))` - Single quote + double parentheses
- `"))` - Double quote + double parentheses

### Comment Characters Summary
- `--` - Standard comment
- `#` - MySQL comment
- `--+` - URL-encoded comment
- `/* */` - C-style comment

### Bypass Techniques Summary
- Mixed case: `SeLeCt`
- Double writing: `SELSELECTECT`
- Encoding bypass: `%53ELECT`
- Inline comments: `/*!SELECT*/`
- Logical closure: `' or '1'='1`

---

**Next Update**: Update progress after completing each stage
