# Social Engineering Command Line Tools Detailed Reference

## 1. SET (Social-Engineer Toolkit) - socialwillengineeringToolpackage

### Core Functionality
SET isOneintegration socialwillengineeringattackframework，providesmultiplekindattacktoamountandautomated successcan。

### Main Attack Modules
- **Spear Phishing Attack Vectors**: Spear Phishing Attack
- **Website Attack Vectors**: websiteattack（clone、Java Appletetc.）
- **Infectious Media Generator**: Infectiousity媒bodygeneratetool
- **Mass Mailer Attack**: large-scalemailpieceattack
- **Arduino-Based Attack Vector**: Arduinohardpieceattack
- **SMS Spoofing Attack Vector**: SMSspoofingattack
- **Wireless Access Point Attack Vector**: nolineAPattack

### Basic Usage
```bash
# startSET（requiresrootpermission）
sudo setoolkit

# Interactive menu navigation
# 1. Social-Engineering Attacks
# 2. Fast-Track Penetration Testing
# 3. Third Party Modules
```

### Spear Phishing Attack
```bash
# Select Attack Type
1. Spear Phishing Attack Vectors

# Select Attack Method
1. Mass Email Attack
2. File Format Exploits
3. Social-Engineering Template

# Configure Email Parameters
- Sender Address
- Recipient List
- Email Subject
- Email Content Template
- Attachment Payload
```

### Website Attack Vectors
```bash
# websiteclone
1. Website Attack Vectors
2. Java Applet Attack Method
3. Site Cloner

# Configuration Parameters
- Target Website URL
- Local Listening IP
- Payload Type
- Social Engineering Template
```

### Practical Points
- Requires root privileges to run
- Integrated Metasploit Payload Generation
- supportsfromdefinitionSocial Engineering Template
- Provides Detailed Attack Logs

## 2. GoPhish - open-sourcephishingToolpackage

### Core Functionality
GoPhish isOneopen-source networkphishingToolpackage，Provides Web Interface and APIinterface，supportslarge-scalephishingactivityManagement。

### Basic Architecture
- **Admin Server**: Managementinterface（default3333port）
- **Phishing Server**: phishingpageserver（default80port）
- **Database**: SQLitedatabasestorage
- **API**: RESTful APIinterface

### Configuration File
```json
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": false,
    "cert_path": "",
    "key_path": ""
  },
  "phish_server": {
    "listen_url": "0.0.0.0:80",
    "use_tls": false,
    "cert_path": "",
    "key_path": ""
  },
  "db_name": "sqlite3",
  "db_path": "gophish.db",
  "migrations_prefix": "db/db_"
}
```

### Basic Usage
```bash
# startGoPhish
gophish

# accessManagementinterface
http://localhost:3333

# defaultlogincredentials
Username: admin
Password: gophish
```

### Core Components
- **Campaigns**: phishingactivityManagement
- **Templates**: mailpiecetemplateManagement
- **Landing Pages**: loginpageManagement
- **Users & Groups**: targetuserManagement
- **Sending Profiles**: mailpiecesendconfiguration

### API Usage
```bash
# obtainAPIkey
# In admin interfaceSettingsingenerate

# createnewactivity
curl -H "Authorization: Bearer YOUR_API_KEY" \
     -H "Content-Type: application/json" \
     -X POST -d '{"name":"Test Campaign"}' \
     http://localhost:3333/api/campaigns/

# obtainactivitystatus
curl -H "Authorization: Bearer YOUR_API_KEY" \
     http://localhost:3333/api/campaigns/
```

### Practical Points
- supportsHTTPSconfiguration
- providesdetailed analysisreport
- can exportCSVformatresult
- supportsfromdefinitiondomain nameandSSLcertificate

## 3. SendEmail - commandrowmailpiecesendTool

### Basic Usage
```bash
# basic mailpiecesend
sendemail -f sender@example.com -t recipient@example.com -u "Subject" -m "Message" -s smtp.example.com

# With attachmentpiece mailpiece
sendemail -f sender@example.com -t recipient@example.com -u "Subject" -m "Message" -a attachment.pdf -s smtp.example.com

# HTMLmailpiece
sendemail -f sender@example.com -t recipient@example.com -u "Subject" -m "<h1>HTML Message</h1>" -o message-content-type=html -s smtp.example.com

# identityverify
sendemail -f sender@example.com -t recipient@example.com -u "Subject" -m "Message" -xu username -xp password -s smtp.example.com:587
```

### Advanced Options
```bash
# TLSencryption
sendemail -f sender@example.com -t recipient@example.com -u "Subject" -m "Message" -o tls=yes -s smtp.gmail.com:587

# fromdefinitionsendpiecepersonName
sendemail -f "Sender Name <sender@example.com>" -t recipient@example.com -u "Subject" -m "Message" -s smtp.example.com

# batchamountsend
while read email; do
    sendemail -f sender@example.com -t $email -u "Subject" -m "Message" -s smtp.example.com
done < recipients.txt
```

### SMTP Configuration
- **Gmail**: smtp.gmail.com:587 (TLS required)
- **Outlook**: smtp-mail.outlook.com:587 (TLS required)
- **Yahoo**: smtp.mail.yahoo.com:587 (TLS required)
- **fromdefinitionSMTP**: based onmailpieceservice商configuration

### Practical Points
- supportsmultiplekindidentityverifymethod
- can sendHTMLandpuretextthismailpiece
- supportsbatchamountmailpiecesend
- providesdetailed logrecord

## 4. Maltego - OSINT(OSINT)andForensicsTool

### Core Functionality
Maltego isOneOSINTandForensicsTool，used forinformation gathering、relationship mappinganddataanalysis。

### Basic Usage
```bash
# startMaltego
maltego

# commandrowmode（has限successcan）
maltego -c /path/to/config -p automationPort

# importdata
maltego -i data.xml

# automated script
maltego -m script.mtz
```

### Transformation Types
- **Domain to DNS**: domain nametoDNSrecord
- **DNS to IP**: DNStoIPaddress
- **IP to Location**: IPto地reasonbitconfiguration
- **Email to Person**: email addresstopersonalinformation
- **Person to Social Media**: personneltosocial media
- **Company to Employees**: companytoemployeeinformation

### Data Sources
- **Built-in Transforms**: built-intransform
- **Public Data Sources**: PublicData Sources
- **Custom Transforms**: fromdefinitiontransform
- **API Integrations**: APIintegration

### Practical Points
- Mainthroughgraphical interfaceoperation
- commandrowMainused forautomated andbatchamounthandling
- requiresconfigurationAPIkeyobtaincomplete successcan
- supportsfromdefinitiontransformdevelopment

## 5. SecLists - security testingdictionarycollection

### Although SecLists is not a tool itself, it is an important resource for social engineering attacks

### Directory Structure
- **Passwords**: passworddictionary
- **Usernames**: usernamedictionary
- **Fuzzing**: fuzzytestingdictionary
- **Web-Content**: Webcontentdictionary
- **Discovery**: discoverydictionary
- **Social Engineering**: socialwillengineeringspecializedusedictionary

### Social Engineering Related Wordlists
- **Passwords/Common-Credentials**: common credentials
- **Usernames/top-usernames-shortlist**: common username
- **Social Engineering/Email Templates**: mailpiecetemplate
- **Social Engineering/Phishing Domains**: phishingdomain namelist

### Usage Examples
```bash
# passwordbrute force
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt target.com ssh

# directorybrute force
gobuster dir -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/common.txt

# subdomain namediscovery
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Practical Points
- regularlyupdateDictionary Files
- based ontargetcustomdictionary
- CombineitsotherTooluse
- noteDictionary Filessizeanditycan

## Tool Combination Usage Strategy

### 1. Phishing Attack Workflow
```bash
# Step 1: targetreconnaissance
maltego - Find target emails and social media information

# Step 2: phishingpagepreparation
setoolkit - Website cloning或GoPhish - Custom login page

# Step 3: mailpiecesend
sendemail - BatchSend phishing email或GoPhish - Manage large-scale campaigns

# Step 4: credentialscollect
metasploit - Handle returned credentials orGoPhish - Analyze clicks and submission data
```

### 2. Social Engineering Reconnaissance Workflow
```bash
# Step 1: OSINTcollect
maltego - CollectTargetOrganization and personal information

# Step 2: dictionarypreparation
seclists - Select appropriate username and password wordlists

# Step 3: customizeattack
setoolkit - Create targeted social engineering attacks

# Step 4: automated execute
sendemail + custom scripts - AutomationEmail sending and tracking
```

### 3. Enterprise Security Testing Workflow
```bash
# Step 1: authorizationandscopeconfirm
# Step 2: employeeinformation gathering
maltego + manual research - Collect employee emails and position information

# Step 3: phishingactivityDesign
gophish - Design professional phishing campaigns and pages

# Step 4: executeandmonitoring
gophish - Executecampaign and real-timeMonitorResults

# Step 5: reportgenerate
gophish + manual analysis - GenerateVerbosesecurity awareness report
```

## Best Practices and Considerations

### 1. Legal and Ethics
- **Absolute Authorization**: Social Engineering Attacks Must Obtain Explicit Written Authorization
- **Scope Limitation**: Strictly Comply with Testing Scope, Do Not Exceed Authorization Boundaries
- **Minimal Impact**: Avoid Causing Unnecessary Distress or Harm to Targets
- **Data Protection**: Properly Handle Collected Sensitive Information

### 2. Technical Best Practices
- **Authenticity**: Phishing Content Should Be as Authentic and Credible as Possible
- **Timing Selection**: Choose Appropriate Time for Attack (Avoid Holidays, etc.)
- **Multi-Channel**: Combine Email, SMS, Phone and Other Channels
- **Tracking and Analysis**: Detailed Recording and Analysis of Attack Effectiveness

### 3. Evasion of Detection
- **Domain Selection**: Use Similar or Trusted Domains
- **Email Content**: Avoid Obvious Spam Characteristics
- **Sending Frequency**: Control Sending Rate to Avoid Being Flagged
- **Technical Bypass**: Use HTTPS, Legitimate SMTP Servers, etc.

### 4. Effectiveness Evaluation
- **Click Rate**: Measure Email Opens and Link Clicks
- **Submission Rate**: Measure Form Submissions and Credential Leaks
- **Report Quality**: Generate Valuable Improvement Recommendations
- **Training Effectiveness**: Provide Materials for Security Awareness Training

## Common Issues and Solutions

### 1. Email Marked as Spam
- Use Legitimate SMTP Servers
- Avoid Spam Keywords
- Set Correct SPF/DKIM/DMARC Records
- ControlSending Frequencyandnumberamount

### 2. Phishing Page Flagged by Browser
- Use Valid SSL Certificates
- Avoid Obvious Malicious Characteristics
- Use Trusted Domains
- Regularly Update Page Content

### 3. Insufficient Target Information
- Combine Multiple OSINT Tools
- Manually Search and Verify Information
- Utilize Social Media and Public Information
- Build Target Profile

### 4. Complex Tool Configuration
- Use Pre-configured Templates
- Reference Official Documentation and Community Resources
- Incrementally Test and Verify Configuration
- Establish Standardized Operational Procedures