# Automated DevSecOps Security Platform

ระบบกลางสำหรับตรวจความปลอดภัยของ GitHub Repositories ด้วย **Bandit, Trivy และ Gitleaks** พร้อม Dashboard สำหรับดูผลของแต่ละ Repository, Branch และ Commit

## 1. ระบบทำงานอย่างไร

```text
Push โค้ดเข้า Repository
        ↓
GitHub Actions เรียก Central Security Platform
        ↓
Bandit / Trivy / Gitleaks สแกนและสร้างรายงาน
        ↓
Central ตรวจรายงาน → คำนวณ Score / Grade → ตัดสิน ALLOW หรือ BLOCK
        ↓
GitHub Actions เก็บรายงานใน Artifact ชื่อ security-reports
        ↓
Dashboard ใช้ GitHub App ดึงผล → บันทึก SQLite → แสดงผลและประวัติ
```

| ส่วน | หน้าที่ |
|---|---|
| **Central Security Platform** | รัน Scanner ตรวจข้อผิดพลาดและรายงาน คำนวณคะแนน และตัดสิน Policy |
| **Dashboard** | ดึงผลจาก GitHub Actions แล้วแสดง Repository, Branch, Commit, Findings และประวัติ |

Workflow ยังทำงานกับ Pull Request เข้า `main` เพื่อใช้ตรวจสอบก่อน Merge ส่วน Dashboard ติดตามผลจาก **Push runs** และไม่ใช้ผลของ PR merge commit แทนผลของ Branch

**การเพิ่ม URL ใน Dashboard ไม่ได้สร้าง Workflow ให้ Repository** ต้องตั้งค่า Workflow ตามข้อ 3 และ GitHub App ตามข้อ 4 ก่อน จึงจะดึงผลมาแสดงได้

## 2. ติดตั้งและเปิด Dashboard บน Windows

### 2.1 ติดตั้ง Dependencies

ใช้ **Python 3.13** และรันจากโฟลเดอร์ `devsecops-security-platform`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

หากมี `.venv` แล้ว ไม่ต้องสร้างใหม่ สามารถใช้ `.\.venv\Scripts\python.exe` แทน `python` ได้โดยไม่ต้อง Activate

Dashboard ที่ดึงผลจาก GitHub Actions ไม่ต้องติดตั้ง Trivy และ Gitleaks บนเครื่องที่เปิดเว็บ เพราะ Central Action ติดตั้งเครื่องมือบน GitHub Runner ให้ ส่วนการสแกนผ่าน CLI บนเครื่องต้องมี Bandit, Trivy และ Gitleaks ใน `PATH`

### 2.2 เตรียมการตั้งค่า

สร้าง `.env` จาก Template เฉพาะเมื่อยังไม่มีไฟล์:

```powershell
if (-not (Test-Path -LiteralPath .env)) {
    Copy-Item -LiteralPath .env.example -Destination .env
}
```

แก้ `.env` ให้ตรงกับเครื่องและ GitHub App ของคุณ โดยดูข้อ 4 และข้อ 8 ประกอบ **อย่าเขียนทับ `.env` เดิมหากตั้งค่าไว้แล้ว**

### 2.3 สร้าง Super User คนแรก

```powershell
python -m auth.bootstrap --username admin
```

ระบบจะถามรหัสผ่านและให้ยืนยันโดยไม่แสดงสิ่งที่พิมพ์:

- Username ยาว 3–64 ตัว ใช้ตัวอักษรอังกฤษ ตัวเลข `_`, `.` และ `-`
- Password ยาว 8–128 ตัวอักษร ไม่มีรหัสผ่านเริ่มต้น
- ใช้สร้าง Super User คนแรก ไม่เขียนทับบัญชีเดิม หากมีบัญชีแล้วให้ Login ด้วยบัญชีที่มีอยู่

ค่าเริ่มต้นใช้ฐานข้อมูล `devsecops.db` ในโฟลเดอร์โปรเจกต์ หากเปลี่ยน `DEVSECOPS_DATABASE_PATH` ใน `.env` ต้องตั้ง Environment Variable ให้คำสั่ง Bootstrap ใช้ฐานข้อมูลเดียวกันด้วย ตัวอย่างสำหรับ Path ที่เตรียมโฟลเดอร์ไว้แล้ว:

```powershell
$env:DEVSECOPS_DATABASE_PATH = 'C:\data\devsecops\platform.db'
python -m auth.bootstrap --username admin
```

### 2.4 เปิดระบบ

```powershell
.\start-dashboard.ps1
```

เปิด <http://127.0.0.1:8000/dashboard/login.html> แล้ว Login ด้วยบัญชีที่สร้าง ให้เปิด Backend ค้างไว้เพื่อให้ระบบดึงผลอัตโนมัติ

`start-dashboard.ps1` โหลด `.env` ให้ Server ส่วนการเรียก Bootstrap หรือ Uvicorn โดยตรงไม่ได้โหลดการตั้งค่าทั้งหมดจาก `.env` อัตโนมัติ การตั้งค่า GitHub App มีตัวอ่าน `.env` ใน Backend แยกต่างหาก

## 3. เชื่อม Repository กับ Central Security Platform

แนะนำชื่อไฟล์ **`security-gate.yml`** สำหรับใช้งานจริง เพื่อสื่อว่าเป็น Workflow ตรวจ Security Gate และใช้ชื่อเดียวกันได้ทุก Repository

ใน Repository ที่ต้องการสแกน เช่น `devsecops-security-test` ให้สร้างไฟล์:

```text
.github/workflows/security-gate.yml
```

ใส่ YAML นี้ **หากมี Workflow นี้อยู่แล้ว ไม่ต้องสร้างซ้ำ**:

```yaml
name: Security Gate

on:
  push:
    branches:
      - "**"
  pull_request:
    branches:
      - main

permissions:
  contents: read

jobs:
  security:
    name: Central Security Gate
    uses: TRM-MYOS/devsecops-security-platform/.github/workflows/security-scan.yml@main
```

Workflow นี้เรียก Central เมื่อ **Push ทุก Branch** หรือ **เปิด/อัปเดต Pull Request เข้า `main`** โดย Central ดูแลการติดตั้งเครื่องมือ สแกน และตัดสิน ALLOW/BLOCK ทั้งหมด

ชื่อไฟล์ต้องตรงกับ **Workflow filename** ในหน้า **Owner Settings** ซึ่งใช้ร่วมกันทุก Repository หากยังไม่บันทึกผ่าน Dashboard ระบบอ่าน `DEVSECOPS_GITHUB_WORKFLOW` จาก Environment / `.env` และใช้ `security-gate-test.yml` เป็น Default เมื่อไม่ได้กำหนด หากจะเปลี่ยนชื่อเป็น `security-gate.yml` ให้เปลี่ยน Workflow ใน Repository ที่ติดตามให้ตรงกันก่อน การแก้ตัวอย่างใน README ไม่ได้เปลี่ยนไฟล์ที่ใช้งานจริงให้เอง

สิ่งที่ต้องตั้งค่าให้ครบ:

1. ไฟล์ Workflow ต้องอยู่ใน Repository และ Revision ที่ GitHub ใช้รันจริง การวางโค้ดไว้ใน README หรือแก้ไฟล์เฉพาะบนเครื่องยังไม่ทำให้ GitHub Actions ใช้การเปลี่ยนแปลงนั้น
2. หาก Central เป็น Private ต้องเปิดสิทธิ์ให้ Repository ที่เรียกใช้ Private Action และ Reusable Workflow ได้ การตั้งค่านี้แยกจาก GitHub App ของ Dashboard ตัวเชื่อมนี้ไม่ใช้ PAT หรือ `CENTRAL_REPO_TOKEN`
3. คงชื่อ Job `Central Security Gate` ในตัวเชื่อม และ `Run Central Security Scan` ใน Central เพราะตัวนำเข้ารายงานตรวจชื่อ Job นี้ด้วย อย่าเพิ่ม Job ผลิตรายงานอื่นในตัวเชื่อม
4. ตั้ง Branch Protection / Ruleset ของ `main` ให้ Require Status Check ชื่อ **`Central Security Gate / Run Central Security Scan`** จาก GitHub Actions เพื่อบังคับห้าม Merge เมื่อ Gate ไม่ผ่าน
5. ป้องกัน Branch `main` ของ Central และให้ตรวจทานการเปลี่ยน Workflow, Action, Scanner และ Policy เพราะตัวเชื่อมอ้างอิง `@main`

ดูการทำงานได้ที่แท็บ **Actions** ของ Repository เป้าหมาย รายงานอยู่ใน Artifact ชื่อ `security-reports` ซึ่งอัปโหลดด้วย `if: always()` แม้ Gate ไม่ผ่าน ทั้งนี้ Scanner ที่ล้มเหลวอาจสร้างรายงานได้ไม่ครบ

## 4. ตั้งค่า GitHub App เพื่อให้ Dashboard อ่านผล

Backend ใช้ GitHub App อ่านข้อมูล Repository, Workflow runs และ Artifacts รวมถึง Repository แบบ Private

1. สร้าง GitHub App และให้ Repository Permissions: **Metadata: Read**, **Contents: Read** และ **Actions: Read**
2. ติดตั้ง App ในบัญชีเจ้าของ Repository แล้วเลือก Repositories ที่ต้องการให้ Dashboard อ่าน
3. สร้าง Private Key เก็บไฟล์ `.pem` ไว้นอกโปรเจกต์
4. เปิด Dashboard ด้วย Super User แล้วกรอก Owner และค่าของ App ใน **Owner Settings** จากนั้น Test connection และ Save settings ตามข้อ 5 หรือเตรียมค่าเริ่มต้นใน `.env` ก่อนเปิด Backend โดยใช้ข้อมูลของคุณแทน Placeholder:

```dotenv
DEVSECOPS_GITHUB_APP_ID=YOUR_APP_ID
DEVSECOPS_GITHUB_INSTALLATION_ID=YOUR_INSTALLATION_ID
DEVSECOPS_GITHUB_PRIVATE_KEY_PATH="C:\secure\github-app.private-key.pem"
DEVSECOPS_GITHUB_WORKFLOW=security-gate.yml
```

5. หากตั้งผ่าน Dashboard ใช้ได้ในรอบ Sync ถัดไปโดยไม่ Restart หากตั้งผ่าน `.env` ก่อนบันทึกค่าในฐานข้อมูล ให้ Restart Backend แล้วเพิ่ม Repository ผ่าน Dashboard

ระบบนี้ใช้การดึงข้อมูลเป็นรอบ จึงไม่ต้องตั้ง Webhook หรือ OAuth สำหรับผู้ใช้ ดูขั้นตอนและข้อจำกัดเพิ่มเติมใน [คู่มือ GitHub monitoring](docs/github-monitoring.md)

อย่าใส่ Password, Token หรือเนื้อหา Private Key ลง README, Workflow หรือ Git ระบบเก็บเพียง Path ของไฟล์ Key ในการตั้งค่า และต้องจำกัดสิทธิ์เข้าถึงไฟล์จริง

## 5. ใช้งาน Dashboard

| หน้า | ใช้ทำอะไร |
|---|---|
| **Dashboard** | ดูผลล่าสุดของแต่ละ Branch พร้อมสถานะและจำนวน Findings |
| **Repository Monitoring** | เพิ่ม URL เลือก Repository ดู Branch และสั่ง Sync ผล |
| **Scan History** | ตารางประวัติตามสิทธิ์ พร้อม Search, Filter และแบ่งหน้า; View เปิดหน้า Scan details |
| **Scan details** | รายละเอียด Commit เดียว ตัวกรอง Scanner/Severity/ไฟล์ และแบ่งหน้า Findings |
| **Repository members** | Super User หรือ Operator ของ Repository จัดสมาชิก; Viewer ไม่เห็นรายชื่อ |
| **Security Policy** | ทุก Role อ่านได้; Super User บันทึกเกณฑ์คะแนนและตรวจสถานะการนำไปใช้กับ Runner |
| **User Management** | Super User จัดการบัญชี สิทธิ์ และดู Audit log |

### เพิ่ม Repository และดูผลครั้งแรก

1. Login ด้วย Operator หรือ Super User
2. ไปที่ **Repository Monitoring** ใส่ URL เช่น `https://github.com/TRM-MYOS/devsecops-security-test` แล้วกด **Add repository**
3. ระบบดึงผลครั้งแรกและค้นหา Branch ให้อัตโนมัติ ไม่ต้องกรอกชื่อ Branch ทีละรายการ
4. Push โค้ดที่เข้าเงื่อนไข Workflow แล้วรอ GitHub Actions สแกนเสร็จ
5. ดูผลบน Dashboard หรือกด Branch เพื่อเปิด History และรายละเอียด เช่น **Affected file**, **Line** และลิงก์ไฟล์ของ Commit นั้น

Dashboard รับ URL ภายใต้ **GitHub Owner** ที่ตั้งในหน้า **Owner Settings** โดยค่าเริ่มต้นเป็น **TRM-MYOS** Super User เห็นทุก Repository ส่วน Operator/Viewer เห็นเฉพาะที่เป็นสมาชิก Operator ที่เพิ่ม Repository ใหม่จริงจะเป็นสมาชิกทันที การวาง URL ของรายการเดิมไม่ให้สิทธิ์เข้าร่วมเอง

ปุ่ม **Members** บนรายการ Repository หรือหน้า Monitoring เปิดหน้าจัดสมาชิก ส่วน **Leave repository** ให้ Operator/Viewer ออกด้วยตัวเอง หลังออกแล้วต้องให้สมาชิก Operator หรือ Super User เพิ่มกลับ ประวัติยังอยู่สำหรับสมาชิกคนอื่น การอัปเกรดไม่เดาสมาชิกของ Repository เก่า: Super User ต้องจัดสมาชิกให้ก่อน

History คงตารางเดิมและแบ่งครั้งละ 20 รายการ กด **View details** เพื่อเปิดหน้าแยก **Back to history** คืนตัวกรอง หน้า และตำแหน่งเลื่อน Findings แบ่งครั้งละ 20 รายการ กรองแล้วไม่พบรายการไม่ได้เปลี่ยนผล Gate เป็น ALLOW ลิงก์เก่า `history.html?scan=...` ยังส่งต่อไปหน้ารายละเอียดได้

### ตั้งค่าบัญชีและ GitHub App จาก Dashboard

Login ด้วย **Super User** แล้วเปิดเมนู **Owner Settings**:

1. กรอก **GitHub Owner**, **GitHub App ID**, **Installation ID**, **Private Key Path** และ **Workflow filename** ให้เป็นชุดเดียวกัน
2. **Private Key Path** ต้องเป็น Absolute Path ของไฟล์ `.pem` บนเครื่อง Backend เก็บไว้นอกโปรเจกต์ ไม่ใช่ Path บนเครื่องที่เปิด Browser ระบบตรวจว่าเป็น RSA Private Key ที่อ่านได้และไม่แสดงเนื้อหา Key
3. กด **Test connection** เพื่อตรวจ App, Owner ของ Installation, สิทธิ์อ่าน Actions/Contents/Metadata และการอ่านรายการ Repository โดยยังไม่บันทึก การทดสอบนี้ยังไม่ยืนยันว่าแต่ละ Repository มี Workflow หรือ Artifact ที่ถูกต้อง ส่วนนี้ตรวจเมื่อ Sync
4. กด **Save settings** ระบบตรวจการเชื่อมต่อซ้ำก่อนบันทึก SQLite หากข้อมูลผิดหรือ GitHub ติดต่อไม่ได้ ค่าปัจจุบันจะยังอยู่ พร้อมแสดงข้อผิดพลาด
5. รอบ Sync ที่กำลังทำงานจะใช้ค่าชุดเดิมจนจบก่อนบันทึกค่าใหม่ รอบถัดไปใช้ค่าใหม่พร้อม Client/Token ชุดใหม่ **ไม่ต้อง Restart Backend หลัง Save** เปิด Backend ด้วยหนึ่ง Worker ตามคู่มือนี้

ค่าที่บันทึกในฐานข้อมูลมีลำดับความสำคัญเหนือ **Process Environment → `.env` → Default** ทั้งห้าค่าเป็นชุดเดียวกัน จึงเปลี่ยน `.env` อย่างเดียวแล้วไม่ทับค่าที่บันทึกผ่าน Dashboard หากย้ายเครื่องพร้อมฐานข้อมูล ให้แก้ Private Key Path ใน Owner Settings ให้ตรงกับเครื่องใหม่

เมื่อเปลี่ยน Owner ระบบเก็บ Repository, ประวัติและ Findings เดิมไว้ แต่ Repository นอก Owner ใหม่จะขึ้นข้อความหยุดติดตามและไม่มีผล ALLOW/BLOCK ปัจจุบัน ผลใน Scan History ยังคงเป็นหลักฐานของ Commit เดิม เพิ่ม URL ของ Owner ใหม่ใน Repository Monitoring ได้ตามปกติ การเปลี่ยนค่าบันทึก Audit ในหน้า User Management

**ส่วนที่ยังต้องจัดการด้วยมือ:** การติดตั้ง App และสิทธิ์ Repository บน GitHub, Workflow ของ Repository เป้าหมาย และ Branch Protection ส่วนชื่อ Owner ใน `uses:` ของ `.github/workflows/security-scan.yml` กับ Workflow เป้าหมายยังระบุ Central ที่เรียกใช้งาน หากย้าย Central เองต้องตรวจ `TRUSTED_WORKFLOW` ใน `repository/github_monitor.py` ด้วย การเปลี่ยน Owner เป้าหมายใน Dashboard ไม่เปลี่ยน Central ที่เชื่อถือหรือกฎ ALLOW/BLOCK

### Sync และการอัปเดตอัตโนมัติ

- **Sync results**: ดึงผลของ Repository ที่เลือกทันที
- **Sync all**: ดึงผลของทุก Repository ที่เชื่อมไว้
- Backend ตรวจผลบน GitHub เมื่อเริ่มระบบ และเว้นประมาณ **30 วินาทีหลังจบแต่ละรอบ** ระยะจริงขึ้นกับจำนวน Repository, Branch และเวลาที่ GitHub ตอบกลับ
- หน้า Dashboard, Monitoring และ History ที่เปิดอยู่จะอ่านข้อมูลที่บันทึกไว้ทุก **5 วินาที**

**Sync ไม่ได้เริ่มสแกนใหม่** และไม่แก้ Workflow หรือรายงานที่เสียให้เอง ไม่จำเป็นต้องกด Sync ทุกครั้งหาก Backend และการดึงข้อมูลอัตโนมัติทำงานอยู่

### เผยแพร่เกณฑ์คะแนนโดยไม่เปิด Backend ออกอินเทอร์เน็ต

Super User ใช้ **Security Policy → Apply policy** และยืนยัน ระบบบันทึก Version ลง SQLite แล้วใช้ GitHub App สร้าง Commit เปลี่ยนเฉพาะ `security-policy.yaml` บน Central `main` โดยตรง **ไม่สร้าง PR** ระบบอ่านกลับจาก GitHub ก่อนแสดง Applied และยังต้องตรวจ Version ในรายงาน Runner รอบใหม่เพื่อยืนยันการใช้งานจริง หาก Apply ล้มเหลว ค่าที่บันทึกในเครื่องยังไม่ถือว่าเปิดใช้บน GitHub ให้ Check GitHub status หรือ Retry apply เวอร์ชันเดิมก่อน

ครั้งแรกต้องเผยแพร่โค้ดที่รองรับฟังก์ชันนี้ และให้ GitHub App เข้าถึง Central พร้อม Contents write และกฎ Branch ที่อนุญาตให้เขียนตรง ตาม [คู่มือ Policy publication](docs/policy-publication.md) ไม่ต้องใช้ Pull requests write สำหรับ Apply ไม่ข้ามกฎ Branch ไม่ใช้ PAT และไม่ต้องเปิด Dashboard/Backend รับ Connection จากอินเทอร์เน็ต

## 6. อ่านผล Score, ALLOW และ BLOCK

คะแนนเริ่มที่ 100 และหักต่อ Finding ตามระดับความรุนแรง:

| Severity | คะแนนที่หักต่อรายการ |
|---|---|
| CRITICAL | 40 |
| HIGH | 25 |
| MEDIUM | 15 |
| LOW | 5 |
| UNKNOWN | 0 |

คะแนนต่ำสุดคือ 0 ส่วน Grade คือ A: 90–100, B: 80–89, C: 70–79, D: 60–69 และ F: ต่ำกว่า 60

Policy ปัจจุบันจาก [security-policy.yaml](security-policy.yaml) และ [security/policy.py](security/policy.py):

- พบ **CRITICAL หรือ HIGH** อย่างน้อยหนึ่งรายการ → **BLOCK**
- คะแนนต่ำกว่า **เกณฑ์ที่ใช้ในรอบนั้น** → **BLOCK** (ค่า Central file เริ่มต้นคือ **60**)
- หากไม่เข้าเงื่อนไขข้างต้น → **ALLOW**

ดังนั้น **คะแนน 75 ก็ BLOCK ได้** เช่น พบ HIGH หนึ่งรายการ คะแนนถูกหัก 25 และติดเงื่อนไข HIGH ด้วย ถึง YAML ระบุ `medium: WARN` แต่ฟังก์ชันตัดสินปัจจุบันคืน ALLOW/BLOCK โดย MEDIUM ยังหักคะแนนและทำให้ BLOCK ได้เมื่อคะแนนต่ำกว่าเกณฑ์

Super User ตั้ง Minimum passing score จำนวนเต็ม 0–100 ในหน้า Security Policy ได้ เก็บค่าและเวอร์ชันใน SQLite พร้อม Audit แต่ **การ Save ไม่ได้แก้เกณฑ์บน GitHub โดยลำพัง** หน้า Policy แสดงว่าต้องตั้ง Runner, รอรายงาน หรือพบเวอร์ชันนั้นในรายงานแล้ว รายละเอียดการเปิดใช้ Policy ที่ลงลายเซ็นอยู่ใน [คู่มือสมาชิกและ Policy](docs/repository-access-and-policy.md) การคำนวณ Score/Grade และ HIGH/CRITICAL BLOCK ยังเหมือนเดิม ผลเก่าไม่ถูกแก้ย้อนหลัง

| ผลการทำงาน | ความหมาย |
|---|---|
| ALLOW | ผ่าน Policy และ Central CLI คืน Exit Code 0 |
| BLOCK | มีผลสแกนที่ประเมินแล้วและไม่ผ่าน Policy; CLI คืน Non-zero |
| Scanner / Report Failure | เครื่องมือหรือรายงานผิดพลาด; CLI คืน Non-zero และไม่ถือว่าผ่าน |
| PENDING / QUEUED / RUNNING | ยังไม่มีผลประเมินสมบูรณ์ของ Commit ปัจจุบัน |
| ERROR / Not evaluated | ดึงหรือยืนยันผลไม่ได้ ไม่มีคำตัดสิน ALLOW สำหรับ Commit นั้น |

Central ตรวจ Return Code และ JSON ของ Scanner ทั้งสามตัวก่อนประเมิน Policy ไม่สร้าง JSON ว่างทดแทนการสแกนที่ล้มเหลว และมี Timeout ต่อ Scanner เริ่มต้น **600 วินาที**

## 7. ประวัติ ข้อมูล และสิทธิ์ผู้ใช้

SQLite เก็บบัญชี Session, Repositories, ผลสแกน Findings และข้อมูล Workflow run/attempt หาก Restart โดยใช้ฐานข้อมูล Path เดิม ข้อมูลจะยังอยู่ การเพิ่มตารางเป็นแบบ Additive ไม่ลบข้อมูลเดิม ควรสำรองฐานข้อมูลก่อนอัปเกรดระบบ

History นำเข้าจาก Push workflow runs ที่ GitHub ยังเก็บไว้ รวมทั้งความล้มเหลวที่ไม่มีผล Policy แต่ **ไม่สามารถรับประกันประวัติทุก Push** หาก Push นั้นไม่มี Workflow run หรือ Run/Artifact ถูกลบหรือหมดอายุ ผลเดิมยังดูได้ใน History แต่ไม่ใช้แทนผลของ Commit ใหม่

| การทำงาน | Viewer | Operator | Super User |
|---|---|---|---|
| ดู Dashboard, Findings และ History | เฉพาะสมาชิก | เฉพาะสมาชิก | ทุก Repository |
| อ่าน Policy | ✓ | ✓ | ✓ |
| เพิ่ม Repository ใหม่ | — | ✓ เป็นสมาชิกทันที | ✓ ไม่ต้องเป็นสมาชิก |
| Sync ผลเดี่ยว/ทั้งหมด | — | เฉพาะสมาชิก | ทุก Repository |
| ดู/เพิ่มสมาชิก | — | เฉพาะ Repository ที่เป็นสมาชิก | ทุก Repository |
| ถอน Viewer จาก Repository | — | เฉพาะ Repository ที่เป็นสมาชิก | ✓ |
| ถอน Operator จาก Repository | — | — | ✓ |
| ออกจาก Repository ด้วยตัวเอง | ✓ | ✓ | ไม่ต้องเป็นสมาชิก |
| ลบ Repository | — | — | ✓ |
| แก้เกณฑ์คะแนนผ่าน / Owner Settings | — | — | ✓ |
| สร้าง/เปิด/ปิดบัญชี และเปลี่ยน Role | — | — | ✓ |
| ลบบัญชีผู้อื่น และ Reset password | — | — | ✓ |
| ดู Audit log การเปลี่ยนบัญชี/สิทธิ์ | — | — | ✓ |

ไม่มีการสมัครบัญชีสาธารณะ ให้ Super User สร้างบัญชีผ่าน **User Management** การเปลี่ยน Role หรือปิดบัญชีจะยกเลิก Session ที่เกี่ยวข้อง ระบบป้องกันการปิดบัญชีหรือลดสิทธิ์ Super User ที่ใช้งานได้คนสุดท้าย

ใน **User access** ปุ่ม **Delete** ลบบัญชีถาวรหลังยืนยัน โดยห้ามลบบัญชีตัวเองหรือ Super User ที่ Active คนสุดท้าย ส่วน **Reset password** ให้กรอกรหัสใหม่และยืนยัน 8–128 ตัวอักษร ทั้งสองการทำงานยกเลิก Session ของบัญชีเป้าหมายและเก็บ Audit ไว้ หาก Reset รหัสตัวเองจะต้อง Login ใหม่ การ Reset ไม่เปิดบัญชีที่ Disabled และไม่แสดงรหัสผ่านเดิม

Password เก็บเป็น Argon2id hash และ Session ID เก็บเป็น Hash ในฐานข้อมูล Cookie เป็น HttpOnly/SameSite และ API ที่เปลี่ยนข้อมูลตรวจ Session, Role และ CSRF

## 8. การตั้งค่าและ API สำหรับผู้ดูแล

### Environment Variables หลัก

| ตัวแปร | ค่าเริ่มต้น Development | ความหมาย |
|---|---|---|
| `DEVSECOPS_ENV` | `development` | เลือก Development หรือ Production |
| `DEVSECOPS_DATABASE_PATH` | `devsecops.db` ใน Root โปรเจกต์ | Path SQLite ต้องตรงกันระหว่าง Bootstrap และ Server |
| `DEVSECOPS_ALLOWED_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | Origins คั่นด้วย Comma ไม่ใช้ Wildcard หรือ Slash ท้าย URL |
| `DEVSECOPS_COOKIE_SECURE` | `false` | Production ต้องใช้ `true` และ HTTPS |
| `DEVSECOPS_SESSION_TTL_SECONDS` | `28800` | อายุ Session 8 ชั่วโมง |
| `DEVSECOPS_LOGIN_MAX_ATTEMPTS` | `5` | จำนวนครั้งที่ลอง Login ได้ในช่วงเวลา |
| `DEVSECOPS_LOGIN_WINDOW_SECONDS` | `900` | ช่วงจำกัด Login 15 นาที |
| `DEVSECOPS_SCANNER_TIMEOUT_SECONDS` | `600` | Timeout ต่อ Scanner ใน Process ที่สแกนจริง |
| `DEVSECOPS_GITHUB_WORKFLOW` | `security-gate-test.yml` | ค่าเริ่มต้นในโค้ดเดิม; ตั้งเป็น `security-gate.yml` เมื่อใช้ชื่อตามตัวอย่างนี้ครบทุก Repository |
| `DEVSECOPS_GITHUB_OWNER` | `TRM-MYOS` | Owner เป้าหมายเมื่อยังไม่มีค่าที่บันทึกใน Owner Settings |
| `DEVSECOPS_GITHUB_POLL_ENABLED` | `true` | เปิดการ Sync อัตโนมัติใน Backend |
| `DEVSECOPS_POLICY_SIGNING_KEY_PATH` | ไม่กำหนด | Path ของ Ed25519 Private Key แยกสำหรับเผยแพร่ Policy; ไม่ใช้ GitHub App Key |

ใช้ Uvicorn **หนึ่ง Worker** เพื่อไม่ให้เกิด Poller ซ้ำ การตั้ง Timeout ใน Dashboard ไม่ได้เปลี่ยนค่าใน GitHub Runner

สำหรับ Production ให้ใช้ HTTPS ผ่าน Reverse Proxy กำหนด Trusted Proxy IPs และ Origins ให้ตรงเว็บไซต์จริง จำกัดสิทธิ์ไฟล์ฐานข้อมูล/Private Key และไม่เปิด Development Server ต่อสาธารณะโดยตรง ตัวอย่าง Environment สำหรับฐานข้อมูลที่เตรียมโฟลเดอร์ไว้แล้ว:

```powershell
$env:DEVSECOPS_ENV = 'production'
$env:DEVSECOPS_ALLOWED_ORIGINS = 'https://security.example.com'
$env:DEVSECOPS_COOKIE_SECURE = 'true'
$env:DEVSECOPS_DATABASE_PATH = 'C:\data\devsecops\platform.db'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

### API ที่ใช้บ่อย

| Endpoint | หน้าที่ |
|---|---|
| `GET /health` | ตรวจว่า API ตอบสนอง ไม่ยืนยันความพร้อมของ Scanner หรือ GitHub App |
| `GET /api/auth/csrf` | สร้าง Anonymous Session และรับ CSRF Token สำหรับ Login |
| `POST /api/auth/login` | Login ด้วย Username/Password และหมุน Session |
| `GET /api/auth/me` | อ่านผู้ใช้และ CSRF Token ปัจจุบัน |
| `POST /api/auth/logout` | Logout และยกเลิก Session |
| `GET /api/repositories` / `POST /api/repositories` | ดูรายการ / เพิ่ม Repository |
| `GET /api/github/status` | ตรวจว่ามีการตั้งค่า App โดยไม่ส่ง Credentials กลับ |
| `GET /api/owner-settings` | Super User อ่านค่าการเชื่อมต่อปัจจุบันและแหล่งที่มา |
| `POST /api/owner-settings/test` | Super User ทดสอบค่าที่กรอก โดยไม่บันทึก ต้องมี CSRF |
| `POST /api/owner-settings` | Super User ตรวจการเชื่อมต่อซ้ำและบันทึก SQLite พร้อม Audit ต้องมี CSRF |
| `POST /api/repositories/{id}/sync` | Sync Branch ของ Repository ที่เลือก |
| `POST /api/github/sync` | Sync ทุก Repository |
| `GET /api/scans` | อ่านประวัติที่บันทึกไว้ |
| `GET /api/scans/{id}/findings` | อ่าน Findings ของผลสแกนที่มีรายงานยืนยันแล้ว |
| `GET /api/policy` | อ่าน Policy และเกณฑ์คะแนน |
| `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}` | Super User จัดการบัญชี |
| `DELETE /api/users/{id}` | Super User ลบบัญชีผู้อื่นและยกเลิก Session |
| `POST /api/users/{id}/password` | Super User Reset รหัสผ่านด้วย `password` และ `confirm_password` พร้อมยกเลิก Session |
| `GET /api/users/audit` | Super User ดู Audit log |

API ที่เปลี่ยนข้อมูลต้องส่ง Cookie และ `X-CSRF-Token` ผู้ไม่ Login ได้ HTTP 401 และผู้ไม่มีสิทธิ์ได้ HTTP 403 หน้า `/docs`, `/redoc` และ `/openapi.json` เปิดเฉพาะ Development

## 9. โครงสร้างโปรเจกต์

| Path | หน้าที่ |
|---|---|
| `dashboard/` | HTML, CSS และ JavaScript ของเว็บ |
| `dashboard/scripts/` | JavaScript ส่วนกลางใน `common.js` และไฟล์แยกตามหน้า |
| `dashboard/css/` | สีและตัวอักษรใน `base.css`, โครงหน้าใน `layout.css`, ส่วนใช้ร่วมใน `components.css` และ CSS เฉพาะหน้า |
| `api/` | FastAPI Routes และการจัดการข้อผิดพลาด |
| `auth/` | บัญชี Password, Session และสิทธิ์ |
| `repository/` | SQLite และการดึงผลจาก GitHub |
| `scanner/` | คำสั่ง Scanner และ CLI หลัก |
| `security/` | ตรวจรายงาน Parse, Score และ Policy |
| `security-policy.yaml` | เกณฑ์ Policy |
| `.github/workflows/`, `action.yml` | Reusable Workflow และ Composite Action |
| `tests/` | ชุดทดสอบ Regression |
| `docs/` | คู่มือเพิ่มเติม |
| `start-dashboard.ps1` | เปิด Server โดยโหลด `.env` |
| `.env.example` / `.env` | Template / การตั้งค่าเฉพาะเครื่อง โดย `.env` ถูก Ignore |
| `devsecops.db`, `backups/` | ฐานข้อมูลเริ่มต้นและ Backup เฉพาะเครื่อง ถูก Ignore |
| `reports/` | รายงานที่สร้างจากการสแกน ถูก Ignore |
| `.venv/`, `.pytest_cache/`, `__pycache__/` | Environment และ Cache ที่สร้างระหว่างใช้งาน |

## 10. ทดสอบและแก้ปัญหาเบื้องต้น

### รัน Tests

ใช้ Python Environment ที่ติดตั้ง Dependencies แล้ว ส่วนการทดสอบ JavaScript ต้องมี Node.js:

```powershell
python -m pip check
python -m pytest -q
Get-ChildItem dashboard/scripts/*.js | ForEach-Object { node --check $_.FullName }
node --test tests/dashboard-ui.test.cjs
```

Tests ใช้ฐานข้อมูลชั่วคราวและ Mock การเชื่อมต่อ GitHub/Scanner ร่วมกับการทดสอบ Process Timeout และ Restart ด้วยฐานข้อมูลแยก ไม่แทนที่ฐานข้อมูลใช้งานจริง ครอบคลุม Auth, CSRF, Role, Report Validation, History และ ALLOW/BLOCK ทั้งนี้ยังควรตรวจครบวงจรกับ Repository ที่ได้รับอนุญาตและตรวจหน้าจอทั้ง Desktop/Mobile ก่อนส่งงาน

### เมื่อผลไม่ขึ้น

| อาการ | ตรวจอะไร |
|---|---|
| `GitHub App is not configured` | Super User ตรวจ App ID, Installation ID และ Path ของ Key ใน Owner Settings แล้ว Test/Save; ไม่ต้อง Restart หลัง Save |
| GitHub ตอบ 404 / ไม่มีสิทธิ์ | App ติดตั้งกับ Repository นั้นและมี Contents/Actions Read หรือไม่ รวมถึง Workflow ที่ตั้งไว้มีอยู่จริงหรือไม่ |
| Branch เป็น PENDING / Not evaluated | Commit ล่าสุดมี Workflow run ที่ตรงกันหรือไม่ และสแกนเสร็จหรือยัง |
| Report หาย/ผิดรูปแบบ | ดู Log และ Artifact `security-reports` บน GitHub Actions; ระบบจะไม่เปลี่ยนเป็น ALLOW ทดแทน |
| ผลยังเก่า | รอรอบอัตโนมัติ หรือกด Sync; ตรวจว่า Backend ยังทำงานและ Polling ไม่ถูกปิด |
| Login แล้วไม่เห็นข้อมูลเดิม | ตรวจว่า Server และ Bootstrap ใช้ฐานข้อมูล Path เดียวกัน |
| GitHub Actions ไม่ผ่านแต่ยัง Merge ได้ | ตรวจ Required Status Check และสิทธิ์ Bypass ใน Branch Protection / Ruleset |

คู่มือรายละเอียด: [GitHub App และการติดตามผล](docs/github-monitoring.md) · [การตรวจ Workflow/Artifact และการเตรียมใช้งานจริง](docs/github-monitoring.md#trusted-producer-and-deployment-checks)
