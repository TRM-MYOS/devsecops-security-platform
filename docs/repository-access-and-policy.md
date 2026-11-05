# Repository access, Scan details และ Policy

## อัปเกรดข้อมูลเดิม

`initialize_database()` เพิ่ม `repository_members`, `policy_settings` และ `scan_policy` แบบ `CREATE TABLE IF NOT EXISTS` โดยไม่ลบหรือรวมข้อมูลเดิม ไม่แจกสมาชิกอัตโนมัติให้บัญชีเก่า Super User เห็นทุก Repository และต้องเพิ่มสมาชิกให้ Operator/Viewer ก่อนผู้ใช้เหล่านั้นจึงจะเห็นข้อมูลเดิม

หาก URL เดิมซ้ำกันในรูปแบบตัวพิมพ์ `.git` หรือ `/` ระบบไม่รวมประวัติเองและจะปฏิเสธการเพิ่ม URL ที่กำกวม ให้ Super User ตรวจรายการเดิมก่อน การเพิ่มผ่าน HTTP ใหม่ตรวจ identity ภายใต้ `BEGIN IMMEDIATE` จึงไม่เปิดให้การเพิ่มพร้อมกันหรือ URL อีกรูปแบบทำให้ผู้ไม่มีสิทธิ์เข้าร่วมเอง

Super User ไม่ถูกเพิ่มและไม่แสดงในสมาชิก เมื่อเลื่อน Role เป็น Super User ระบบนำสมาชิกภาพเดิมออก การปิดบัญชียกเลิก Session และไม่ให้ใช้สมาชิกภาพที่เก็บอยู่ หากเปิดบัญชีกลับ สมาชิกภาพเดิมยังอยู่ตามเดิม การลบบัญชีล้างสมาชิกภาพด้วย Foreign Key โดยเก็บ Audit ไว้

## จัดสมาชิก

- Super User: เปิด **Members** ของ Repository ใดก็ได้
- Operator: เปิดได้เฉพาะที่เป็นสมาชิก เพิ่มบัญชี Operator/Viewer ที่ Active และนำ Viewer ออกได้
- Operator นำ Operator คนอื่นออกไม่ได้ และไม่เปลี่ยน Role บัญชี
- Viewer ไม่เห็นรายชื่อสมาชิกหรือเมนู Members
- Operator/Viewer ใช้ **Leave repository** เพื่อออกด้วยตัวเอง แม้เป็น Operator คนสุดท้าย
- หลังออกต้องให้ Operator ที่เป็นสมาชิกหรือ Super User เพิ่มกลับ การวาง URL เดิมไม่ช่วยให้กลับเข้าได้

Remove member ไม่ใช่ Delete user และไม่ลบ Scan/Findings การถอนสิทธิ์มีผลต่อ Request ถัดไป หน้าที่เปิดอยู่ตรวจสิทธิ์ซ้ำระหว่าง Refresh และล้างข้อมูลเมื่อไม่มีสิทธิ์

API ตรวจสิทธิ์ทั้งรายการ รายตัว History, Findings และ Sync รวม โดย `/api/users` และ Owner Settings ยังเป็น Super User เท่านั้น Poller ภายในยังติดตาม Repository ของระบบ ส่วน Sync all จาก Operator ทำเฉพาะรายการที่มีสิทธิ์

สมาชิกบน Dashboard เป็นสิทธิ์ของระบบนี้ ไม่ได้เพิ่ม Collaborator หรือเปลี่ยนสิทธิ์บน GitHub ลิงก์ Open file on GitHub ยังขึ้นกับสิทธิ์บัญชี GitHub ของผู้เปิดลิงก์

## History และ Scan details

History คงตาราง Search/Filter/Breadcrumb เดิม และแบ่งครั้งละ 20 รายการ ข้อมูลและสถิติถูกจำกัดจาก Backend ก่อนส่งมา หน้า `scan-detail.html?scan=...` เปิดผลที่เลือกโดยตรงและไม่เปลี่ยนเป็น Commit ล่าสุดเมื่อ Refresh

Back to history ใช้ Return URL ภายในหน้า History เท่านั้น พร้อมคืน Search, Filter, หน้า และตำแหน่งเลื่อน ลิงก์เก่า `history.html?scan=...` Redirect ไปหน้าใหม่

Findings กรองตาม Scanner, Severity และชื่อไฟล์ เรียง High first หรือ Report order และแบ่งครั้งละ 20 รายการ คง Path เดิม พร้อม Affected file/Line และลิงก์ Commit รายงาน ERROR/PENDING ไม่มี Score หรือ ALLOW ทดแทน การกรองจนไม่เหลือ Finding ไม่เปลี่ยน Gate ของรายงาน

## Minimum passing score

**แนวทางหลักสำหรับเครือข่ายองค์กร:** ใช้ [Apply policy โดยตรงบน Central main](policy-publication.md) โดย Backend เชื่อมออก GitHub และไม่เปิดรับ Connection จากอินเทอร์เน็ต กด Apply ครั้งเดียวเพื่อบันทึก Version และส่ง Commit เฉพาะ Policy โดยไม่สร้าง PR ค่าที่บันทึกในเครื่อง, ค่าที่ตรวจพบบน Central และ Observed in report เป็นคนละสถานะ ส่วน Signed HTTPS ด้านล่างยังเป็นทางเลือกสำหรับผู้ดูแลที่ตั้งใจใช้แหล่ง Policy ผ่านเครือข่ายนั้น

Super User แก้จำนวนเต็ม 0–100 ใน Security Policy ได้ ค่าเป็นเกณฑ์กลางทั้งระบบ ไม่ใช่การแก้คะแนนผลสแกน บันทึกเวอร์ชันใหม่และ Audit ใน SQLite การเปลี่ยนเกณฑ์ไม่แก้ประวัติย้อนหลัง สูตร Score/Grade และ HIGH/CRITICAL BLOCK คงเดิม

Policy ที่ Runner ใช้ถูกแนบใน `security-summary.json` และนำเข้าในประวัติ รวมถึง `scan_policy` สำหรับผลที่บันทึกใหม่ หน้ารายละเอียดแสดงเวอร์ชัน/เกณฑ์ของรอบนั้น หากรายงานเก่าไม่มีข้อมูลนี้จะแสดง Not recorded แทนการใช้เกณฑ์ปัจจุบันเติมย้อนหลัง

### สถานะกรณีใช้ Signed HTTPS

1. **Runner setup required**: บันทึกค่าแล้ว แต่ยังไม่ได้ตั้งแหล่ง Policy ที่ลงลายเซ็นให้ Runner ใช้ อย่าอ้างว่า GitHub ใช้เกณฑ์ใหม่แล้ว
2. **Awaiting Runner report**: Backend มี Key และไฟล์แหล่ง Policy ที่สอดคล้องกันในเครื่อง ยังไม่ยืนยันว่าโค้ดบน GitHub ถูกเผยแพร่แล้ว
3. **Observed in report**: เคยนำเข้ารายงานที่ยืนยันแหล่งที่มาและใช้เวอร์ชันนั้น ไม่ใช่การยืนยันว่างานทั้งหมดบน GitHub ใช้เวอร์ชันนี้แล้ว

### ทางเลือก: เปิดใช้ Signed HTTPS Policy (ไม่จำเป็นสำหรับการเผยแพร่ผ่าน Central)

การทำงานนี้ต้องมี HTTPS Backend ที่ GitHub Runner ติดต่อได้ เครื่อง Dashboard ที่เปิดเฉพาะ `127.0.0.1` ยังไม่ใช่แหล่ง Policy สำหรับ Runner ภายนอก

1. ผู้ดูแลเตรียมที่เก็บ Key นอกโครงการ แล้วสร้าง **Key แยกสำหรับ Policy** ด้วยคำสั่งต่อไปนี้ เลือกชื่อไฟล์ใหม่ คำสั่งไม่เขียนทับไฟล์ที่มีอยู่:

   ```powershell
   python -m security.policy_keys --private-key C:\DevSecOpsKeys\policy-signing.pem
   ```

   เก็บ Private Key ไว้บน Backend และจำกัดสิทธิ์ไฟล์ คำสั่งแสดงเฉพาะ Public Key แบบ Base64 ห้ามใช้ GitHub App Private Key แทน และห้ามนำ Private Key เข้า Git

2. กำหนด `DEVSECOPS_POLICY_SIGNING_KEY_PATH` ให้ Backend ชี้ไฟล์นั้น แล้ว Restart Backend เช่นตั้งใน `.env` ด้วยตนเองหรือ Environment ของบริการ ระบบไม่สร้างหรือแก้ `.env`/Key จริงในระหว่างงานพัฒนานี้

3. ตั้ง HTTPS และให้เข้าถึง **GET `/policy/v1`** ได้ Endpoint นี้เปิดอ่านเฉพาะเอกสาร Policy ที่ลงลายเซ็น มีอายุ 900 วินาที และใช้ `Cache-Control: no-store` ไม่ส่ง Private Key, GitHub Token หรือข้อมูลสมาชิกออกมา คงการป้องกัน Session/Role/CSRF ของ API แก้ไขไว้ตามเดิม

4. ใช้ `security-policy-source.example.json` เป็นแม่แบบสร้าง `security-policy-source.json` ใน Root ของ Central โดยผู้ดูแล:

   ```json
   {
     "url": "https://YOUR-BACKEND/policy/v1",
     "public_key": "BASE64_PUBLIC_KEY_FROM_STEP_1",
     "maximum_age_seconds": 900,
     "required_from": 1234567890
   }
   ```

   `required_from` คือ Unix timestamp UTC ของเวลาที่เริ่มบังคับ Signed Policy สำหรับรายงานใหม่ ใช้ค่าจริงของการเปิดใช้ เช่นอ่านเวลาปัจจุบันด้วย `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()` รายงานก่อนเวลานี้ยังนำเข้าเป็น Legacy ได้โดยไม่เปลี่ยนผลเดิม ส่วนรายงานหลังเวลานี้ต้องมี Signed Policy

5. ใช้ไฟล์แหล่ง Policy ชุดเดียวกันบน Backend และใน Central checkout ที่ Runner ใช้ ไฟล์มีเฉพาะ URL/Public Key ไม่ใช่ข้อมูลลับ แต่ต้องป้องกันการแก้ไขเช่นเดียวกับ Workflow/Scanner ของ Central ตรวจทานและเผยแพร่ไฟล์กับโค้ดผ่านกระบวนการของผู้ดูแล **งานนี้ไม่ได้ Commit/Push/Merge หรือเปลี่ยนสิทธิ์ GitHub ให้**

6. Central Action ติดตั้ง `cryptography` สำหรับตรวจ Ed25519 และอ่านไฟล์แหล่ง Policy จากตำแหน่งของ Central เอง ไม่รับ URL/Public Key/เกณฑ์ผ่าน Input หรือ Environment ของ Repository เป้าหมาย ป้องกันการปลอมเกณฑ์ผ่านตัวเชื่อม โดยไม่ต้องเพิ่ม PAT หรือสิทธิ์เขียนให้ GitHub App

7. ทดสอบ Push ใน Repository ที่ได้รับอนุญาต ตรวจ Required Check เดิม **Central Security Gate / Run Central Security Scan**, ค่า Policy ใน Artifact `security-reports`, เวอร์ชันใน Scan details และสถานะในหน้า Policy ให้ตรงกัน ทดสอบ ALLOW, BLOCK, Policy Failure และตรวจการบล็อก Merge จริงแยกต่างหาก

### Fail-Closed และขอบเขตการทำงาน

ก่อนเปิดใช้ไฟล์แหล่ง Policy ระบบยังใช้ `security-policy.yaml` ของ Central ตามเดิม หลังมีไฟล์แหล่ง Policy แล้ว ถ้า HTTPS ติดต่อไม่ได้ Redirect เอกสารใหญ่เกิน 64 KB ลายเซ็นผิด Key ไม่ตรง Policy หมดอายุ หรือรูปแบบผิด จะหยุดด้วย Policy Failure ไม่มีการถอยกลับไปใช้เกณฑ์ที่อ่อนลง

การเปลี่ยนค่าในหน้า Dashboard อย่างเดียวไม่เผยแพร่ไฟล์ไป GitHub หาก Backend หรือเครือข่ายล่มขณะเปิดใช้ Signed Policy งานใหม่จะไม่ผ่านจนกว่าแหล่ง Policy กลับมา ควรเตรียมบริการที่เข้าถึงได้และนาฬิกาที่ตรงกันก่อนเปิดใช้

ลายเซ็นตรวจความถูกต้องและอายุของเอกสาร กำหนดความคลาดเคลื่อนเวลาสูงสุด 30 วินาที เอกสารที่ลงลายเซ็นไว้ก่อนหน้าอาจยังมีอายุเหลือภายในหน้าต่าง 900 วินาที จึงต้องตรวจเวอร์ชันในรายงานแต่ละ Run แทนการอ้างว่า Save แล้วทุก Run จะเปลี่ยนทันที

การนำเข้ารายงาน Signed Policy ตรวจลายเซ็น ณ เวลา Artifact ถูกสร้างจากข้อมูล GitHub เพื่อรองรับประวัติและไม่ผูกกับเวลาที่ผู้ใช้กด Sync ไม่ใช้เกณฑ์ปัจจุบันประเมินผลเก่าใหม่ ส่วน Cache ของรายงานเดิมที่ผ่านการตรวจแล้วเก็บเป็นหลักฐานเดิมต่อไป

## API ที่เพิ่ม

| Endpoint | สิทธิ์ |
|---|---|
| `GET /api/repositories/{id}/members` | Super User หรือ Operator สมาชิก |
| `GET /api/repositories/{id}/member-candidates?q=...` | เช่นเดียวกัน; ไม่คืน Super User/Hash/Session |
| `POST /api/repositories/{id}/members` | เช่นเดียวกัน; Body `{ "user_id": 123 }` |
| `DELETE /api/repositories/{id}/members/{user_id}` | Super User หรือ Operator นำ Viewer ออก |
| `POST /api/repositories/{id}/leave` | สมาชิกออกด้วยตนเอง; Body `{}`; ต้องมี CSRF |
| `GET /api/scans/{record_id}` | ผู้มีสิทธิ์ Repository ของ Record รวม Run ที่ไม่มีรายงาน |
| `PATCH /api/policy` | Super User และ CSRF; Body `{ "minimum_score": 80 }` |
| `GET /policy/v1` | Public signed policy; 503 หากยังเผยแพร่ไม่ได้ |

การทดสอบใช้บัญชี ฐานข้อมูล Key และ HTTP จำลองแยกจากระบบจริง รวมทั้งตรวจ Browser บน Desktop/Mobile ไม่ถือเป็นหลักฐานการเผยแพร่บน GitHub หรือการบล็อก Merge จริง

## การเปิดใช้และตรวจยืนยันรอบสุดท้าย

### สถานะที่ตรวจจาก GitHub วันที่ 5 พฤศจิกายน 2026

ข้อมูลส่วนนี้เป็นผลตรวจแบบอ่านอย่างเดียว ณ วันดังกล่าว ไม่ใช่สถานะที่อัปเดตอัตโนมัติ

| รายการ | หลักฐานที่ตรวจได้ |
|---|---|
| Central `main` | Commit `e163a99bd7444c6c975605d6b9b0028d6178cc59`; ยังเป็น Policy รุ่นอ่าน YAML และ Action ยังไม่ได้ติดตั้ง `cryptography` |
| Central branch protection | Branch API รายงาน `protected: false`; ผู้ดูแลควรตรวจการป้องกัน Central ก่อนเปิดใช้เกณฑ์แบบออนไลน์ |
| Target `Demo_Test` | มี `.github/workflows/security-gate-test.yml`; อย่าเปลี่ยนชื่อเป็น `security-gate.yml` โดยไม่ปรับ Owner Settings ให้ตรง |
| Target Required Check | Branch API ของ `main` แสดง `Central Security Gate / Run Central Security Scan` ผูกกับ GitHub Actions และ enforcement `everyone` |
| รายละเอียดกฎและ Bypass | Connector อ่าน endpoint branch protection ไม่ได้ (`403`); จึงยังไม่ยืนยันการตั้งค่า Bypass หรือกฎทั้งหมด |
| ผลจริงที่มีอยู่ | [Run 39948672219](https://github.com/TRM-MYOS/Demo_Test/actions/runs/39948672219) สำเร็จ ใช้ Central commit ข้างต้น และมี Artifact `security-reports`; เป็นผลเดิมวันที่ 23 ตุลาคม 2026 ไม่ใช่การทดสอบ Signed Policy รุ่นใหม่ |

### HTTPS ที่จำเป็น

GitHub Runner ต้องอ่าน `GET /policy/v1` จากนอกเครื่อง Dashboard ได้ `127.0.0.1` ของเครื่อง Dashboard ใช้เป็น URL นี้ไม่ได้ ผู้ดูแลเลือกบริการถาวรหรือช่องทางเดโมที่มี HTTPS ก่อน จึงกำหนด URL จริงใน `security-policy-source.json`

เปิดเผยเฉพาะ `GET /policy/v1` ผ่าน Reverse proxy ก็เพียงพอ เส้นทาง `/dashboard/`, `/api/` และเส้นทางอื่นไม่จำเป็นต้องเปิดออกอินเทอร์เน็ตสำหรับการอ่าน Policy ห้ามเปิด Tunnel ไปยัง Backend ทั้งหมดโดยไม่ได้จำกัด Route ก่อน เอกสาร Policy ที่เปิดอ่านมีเกณฑ์คะแนน เวอร์ชัน เวลา และลายเซ็น ไม่มี Private Key หรือข้อมูลผู้ใช้

URL สำหรับเดโมที่เปลี่ยนทุกครั้งต้องปรับไฟล์แหล่ง Policy และเผยแพร่ Central ใหม่ด้วย หากหยุดช่องทาง HTTPS หลังเปิดใช้ Signed Policy แล้ว Gate ใหม่ต้องล้มเหลวแบบ Fail-Closed จนกว่าแหล่ง Policy กลับมา

### ลำดับเปิดใช้

1. เลือก URL HTTPS และ Repository สำหรับทดสอบ ยืนยันว่า Reverse proxy เปิดเฉพาะ Route ที่ต้องใช้
2. ผู้ดูแลสร้าง Policy signing key แยกจาก GitHub App key ตามขั้นตอนด้านบน เก็บนอกโครงการ และตั้ง Environment ของ Backend โดยไม่ส่ง Key ในแชตหรือใส่ Git
3. ตรวจ `GET /policy/v1` จากเครื่องภายนอกว่าตอบ JSON พร้อมลายเซ็นและ `Cache-Control: no-store` ใช้ Public Key ตรวจลายเซ็นให้ผ่าน ไม่ปิดการตรวจ TLS
4. เตรียม `security-policy-source.json` ด้วย URL/Public Key จริงและ `required_from` ที่ตกลงกัน ใช้ชุดเดียวกันบน Backend และ Central
5. ตรวจ Diff ของ `action.yml`, Policy, Parser, source configuration และการทดสอบร่วมกัน แล้วให้ผู้ดูแลเผยแพร่โค้ด Central ที่ตรวจแล้ว การเปลี่ยนไฟล์ในเครื่องเพียงอย่างเดียวยังไม่เปลี่ยน `@main`
6. ทดสอบเกณฑ์ผ่าน API/หน้า Security Policy ด้วย Super User ตรวจสถานะในหน้าเว็บ แต่ยังไม่ถือว่า Runner ใช้เกณฑ์นั้นจนพบเวอร์ชันตรงกันในรายงานใหม่
7. Push กรณีทดสอบที่อนุมัติใน Target แล้วเทียบ Commit, Run/attempt, คะแนน, Gate และ Policy version ระหว่าง Actions, Artifact และ Dashboard
8. ตรวจ PR ที่มีผล BLOCK ว่า GitHub ปิดกั้นการ Merge จริง รวมถึงการ Bypass ของผู้ทดสอบ ห้ามกด Merge เพื่อพิสูจน์การบล็อก

การเผยแพร่ การเปลี่ยนกฎ GitHub การแก้ `.env`/Key จริง และการแก้ Target Repository ต้องให้ผู้ดูแลดำเนินการหรืออนุมัติแยกจากงานเตรียมในเครื่อง

### ตารางหลักฐานทดสอบ

| กรณี | วิธีทดสอบและสิ่งที่ต้องตรงกัน | สถานะ |
|---|---|---|
| ALLOW | ไม่มี Finding ที่ทำให้ BLOCK และคะแนนถึงเกณฑ์; CLI exit 0, Summary ALLOW และ Commit/Policy version ตรงกับ Dashboard | ผ่าน HTTPS ในเครื่องและ Process แยก; GitHub รุ่นใหม่ยังรอเปิดใช้ |
| BLOCK จากคะแนน | Finding MEDIUM หนึ่งรายการให้คะแนน 85; เกณฑ์ 90 ต้อง BLOCK แต่เกณฑ์ 80 ต้อง ALLOW โดย Score ยัง 85 | ผ่าน HTTPS ในเครื่องและ Process แยก; GitHub รุ่นใหม่ยังรอเปิดใช้ |
| HIGH/CRITICAL | ต้อง BLOCK ตามกติกาเดิม แม้เกณฑ์คะแนนเป็น 0 | HIGH ผ่าน Process แยก; HIGH/CRITICAL มี Unit Tests; GitHub รุ่นใหม่ยังรอเปิดใช้ |
| Scanner Failure | เครื่องมือคืนรหัสผิดพลาด; CLI ต้องไม่สำเร็จและต้องไม่มี Summary ALLOW | ผ่าน Process แยกโดยจำลองผลเครื่องมือ; ยังไม่ได้ทำ fault injection บน GitHub |
| Report Failure | รายงานหายหรือ JSON เสีย; CLI ต้องไม่สำเร็จและต้องไม่มี Summary ALLOW | ผ่าน Process แยกโดยจำลองรายงาน; ยังไม่ได้ทำ fault injection บน GitHub |
| Policy Failure | HTTPS โหลด Policy ไม่ได้ หรือเอกสารผิด/ลายเซ็นผิด/หมดอายุ ต้องไม่ใช้เกณฑ์สำรองจนกลายเป็น ALLOW | กรณี HTTPS ไม่พบ Endpoint ผ่าน Process แยก; กรณีเอกสารอื่นมี Unit Tests |
| Restart | บัญชี สมาชิก เกณฑ์ ประวัติ และ Findings ยังอยู่เมื่อเปิด Process ใหม่ด้วย Path ฐานข้อมูลเดิม | มี Tests ใช้ฐานข้อมูลชั่วคราว; ยังไม่ Restart ระบบจริง |

Tests `tests/test_policy_https_integration.py` เปิด FastAPI ผ่าน HTTPS บน Loopback ใช้ Certificate/Signing key/SQLite ชั่วคราว แล้วเรียก CLI Gate ใน Python process แยก โดยจำลองเฉพาะผลของเครื่องมือสแกน การทดสอบนี้ตรวจ HTTP, TLS, การ Save, ลายเซ็น, Parser, Score, Policy และ Exit code ร่วมกัน ไม่ได้ติดตั้งหรือรัน Bandit/Trivy/Gitleaks บน GitHub จริง

สำหรับ Scanner/Report Failure บน GitHub ให้ใช้ Workflow หรือ Branch สำหรับ Validation ที่แยกและตรวจ Diff ก่อน ห้ามเพิ่ม Input ข้าม Policy หรือกลไกปิด Scanner ลงใน Security Gate จริง ห้ามแก้ Central `main` ให้เสียเพื่อทดสอบความล้มเหลว

เมื่อเก็บหลักฐานจริง ให้บันทึก Central SHA, Target SHA, Run ID/attempt, Policy version, Minimum score, Exit code และภาพ PR ที่ปิดกั้น Merge ทุกครั้ง ผลเก่าหรือ Run ที่ใช้ Central รุ่นเดิมไม่ใช่หลักฐานว่าเกณฑ์ใหม่ใช้งานแล้ว
