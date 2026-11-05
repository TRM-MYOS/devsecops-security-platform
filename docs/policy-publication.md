# เปลี่ยนเกณฑ์จาก Dashboard โดยไม่เปิด Backend ออกอินเทอร์เน็ต

## การทำงาน

1. Super User กรอก Minimum passing score 0–100 แล้วกด **Save threshold** เพื่อบันทึกเวอร์ชันที่ต้องการลง SQLite
2. กด **Publish to Central** และยืนยัน ระบบใช้ GitHub App เชื่อมออกไป GitHub สร้าง Branch `dashboard-policy/<version>` และ Pull Request ที่เปลี่ยนเฉพาะ `security-policy.yaml`
3. ผู้มีสิทธิ์ใน Central ตรวจและ Merge PR ตามกฎเดิม ระบบไม่ Merge เองและไม่ข้าม Branch protection
4. กด **Check GitHub status** ระบบตรวจไฟล์บน Central `main` ว่า Minimum score และ Version ตรงกันจริง ก่อนแสดง Published
5. Push โค้ดใหม่ใน Target ให้ Gate ทำงานด้วย Central รุ่นนั้น แล้ว Sync ผลเข้า Dashboard เมื่อรายงานมี Version และเกณฑ์ตรงกันจะแสดง Observed in report

Backend ไม่ต้องเปิดรับ Connection จากอินเทอร์เน็ต และ Runner ไม่ต้องติดต่อ SQLite หรือเครื่อง Dashboard โดยตรง GitHub App private key ไม่ใช่ Policy signing key; วิธีนี้ไม่ต้องสร้าง Policy signing key เพิ่มหรือใช้ PAT

การ Save อย่างเดียวไม่เปลี่ยน Gate บน GitHub และ PR ที่ยังไม่ Merge ยังไม่มีผลต่อเกณฑ์ใหม่ งานที่เริ่มไปแล้วอาจใช้ Central checkout รุ่นก่อนหน้า ให้ตรวจ Policy version ในรายงานของแต่ละ Run

## เปิดใช้ครั้งแรก

### 1. เผยแพร่โค้ด Central ที่รองรับฟังก์ชันนี้

ผู้ดูแลต้องตรวจ Diff, Tests และเผยแพร่โค้ดชุดนี้ตามกระบวนการของ Central ก่อน โดยเฉพาะ Backend/Frontend, Schema migration, `repository/policy_publisher.py`, `security/policy.py` และ Parser ที่บันทึก Policy snapshot

การเผยแพร่โค้ดครั้งแรกเป็นขั้นตอนแยกจากปุ่ม Publish ซึ่งปุ่มนี้เขียนได้เฉพาะไฟล์ Policy ไม่เผยแพร่ Python หรือ Workflow ให้ และไม่เปลี่ยน `uses: ...@main` ให้เอง

หากใช้วิธีเก็บ Policy ใน Central ไม่ต้องสร้าง `security-policy-source.json` สำหรับ HTTPS หากมีไฟล์นั้นอยู่แล้วบน Backend หรือ Central ต้องตรวจทานและเลิกใช้ผ่านกระบวนการที่อนุมัติก่อน ระบบจะปฏิเสธการเผยแพร่แบบ Repository เพื่อป้องกันการอ้างว่าใช้ YAML ทั้งที่ Runner อ่าน HTTPS อยู่

### 2. ตั้ง GitHub App ด้วยผู้ดูแล

App/Installation ที่ Backend ใช้อยู่ต้องเข้าถึง `TRM-MYOS/devsecops-security-platform` และมี Repository permissions:

| Permission | สิทธิ์ |
|---|---|
| Metadata | Read-only |
| Actions | Read-only สำหรับ Monitoring เดิม |
| Contents | Read and write สำหรับเผยแพร่ Policy |
| Pull requests | Read and write สำหรับสร้าง PR |

ผู้ดูแล App ต้อง Save การเปลี่ยนสิทธิ์และอนุมัติ Permission ใหม่ที่ Installation หาก GitHub ร้องขอ ไม่ต้องให้ Workflows write, Administration write หรือสิทธิ์ Bypass กฎ Merge

Token ของ Monitoring ยังขอเฉพาะ read ตามเดิม ส่วน Publisher สร้าง Installation token แยกที่ขอ Contents/Pull requests write และจำกัด Repository เฉพาะ Central โค้ด Publisher กำหนด Repository, Branch `main` และ Path ที่เขียนไว้ฝั่ง Backend ผู้เรียก API เปลี่ยนปลายทางเองไม่ได้

GitHub ไม่ได้จำกัด Contents token ให้เขียนได้เพียงไฟล์เดียว ข้อจำกัดไฟล์อยู่ในโค้ดนี้ด้วย จึงต้องเก็บ App key ให้ปลอดภัยและใช้สิทธิ์ Installation เท่าที่จำเป็น หากองค์กรต้องแยก App สำหรับเผยแพร่ออกจาก App สำหรับอ่านผล ต้องเพิ่มการตั้งค่า Credentials แยกก่อน; รุ่นนี้ใช้ Credentials จาก Owner Settings เดิม

Owner Settings ของ Target ไม่เปลี่ยน Trusted Central ให้เอง หากย้าย Target ไป Owner อื่น Installation ใหม่ยังต้องเข้าถึง Central ได้ด้วย มิฉะนั้นการ Publish จะล้มเหลวอย่างชัดเจน

### 3. ทดสอบใช้งาน

- Login ด้วย Super User → Security Policy → Save threshold → Publish to Central
- ตรวจ PR ว่าเปลี่ยนเฉพาะ Minimum score และ Policy version ใน `security-policy.yaml`; HIGH/CRITICAL ยังเป็น BLOCK
- Merge ด้วยบัญชีที่กฎ Central อนุญาต แล้ว Check GitHub status
- รัน Target ใหม่และตรวจ Run/attempt, Commit, Score, Gate, Policy version และ Minimum score ให้ตรงกับ Artifact/Dashboard
- ตรวจ PR ที่ BLOCK ว่า GitHub ปิดกั้น Merge จริง ข้อความ BLOCK บน Dashboard อย่างเดียวไม่ใช่หลักฐานการปิดกั้น Merge

ก่อนเปลี่ยนเกณฑ์ซ้ำ ให้ตรวจและปิด PR เวอร์ชันเก่าที่ไม่ต้องการ อย่า Merge PR เก่าหลังอนุมัติเวอร์ชันใหม่ การ Save เวอร์ชันใหม่ไม่ลบหรือปิด PR เก่าอัตโนมัติ

## ความหมายของสถานะ

| สถานะ | ความหมาย |
|---|---|
| Not published | ค่าอยู่ใน SQLite เท่านั้น |
| Pull request created / Awaiting merge | สร้าง PR แล้ว แต่ Central `main` ยังไม่ใช้เกณฑ์นั้น |
| Published / Awaiting report | ตรวจพบ Version และ Minimum score บน Central `main`; ยังรอรายงาน Runner ที่ยืนยันเวอร์ชัน |
| Observed in report | เคยนำเข้ารายงานที่ตรวจสอบแล้วและใช้ Version/Minimum score ตรงกัน ไม่ได้ยืนยันว่าทุก Run ใช้เวอร์ชันเดียวกัน |
| Publication failed | สิทธิ์ไม่พอ เครือข่ายล้มเหลว Conflict หรือไฟล์ผิด ไม่ถือว่าเกณฑ์ใหม่มีผล |
| Closed / Superseded | PR ถูกปิด หรือ Central เปลี่ยนไปใช้เวอร์ชันอื่น ให้ Save และเผยแพร่เวอร์ชันใหม่เมื่อจำเป็น |

หาก Request หมดเวลาหลัง GitHub สร้าง Branch/Commit/PR ไปแล้ว ให้ Retry **เวอร์ชันเดิม** หรือ Check status ก่อน ระบบค้นหา Branch/PR จาก Version เพื่อกู้สถานะโดยไม่สร้าง PR ซ้ำตามปกติ หากมีผู้แก้ Branch หรือ `main` เปลี่ยนระหว่างดำเนินการ ระบบไม่เขียนทับให้เอง ต้องตรวจและ Save เวอร์ชันใหม่

## สิทธิ์และผลสแกน

- Save, Publish และ Check publication เป็น Super User เท่านั้น มี Session, CSRF และตรวจสิทธิ์ซ้ำก่อนเขียน GitHub
- Operator/Viewer อ่านค่าและสถานะได้ แต่เรียก API เขียนไม่ได้
- Minimum score เปลี่ยนได้อย่างเดียว สูตร Score/Grade และกติกา HIGH/CRITICAL BLOCK คงเดิม
- เพิ่ม `policy.version` ใน YAML และเก็บ Version/Minimum score ในผลสแกนแต่ละรอบ ไม่แก้ผลเก่าย้อนหลัง
- ถ้า YAML ผิดรูปแบบ Runner ล้มเหลวแบบ Fail-Closed ไม่ใช้ค่า default จนเกิด ALLOW ปลอม
- ข้อผิดพลาดระหว่าง Publish ไม่เปลี่ยน Central `main`; Gate ยังใช้ Policy ที่อนุมัติและเผยแพร่ไว้ก่อนหน้า
- SQLite เพิ่มตาราง `policy_publications` แบบ Additive เก็บ Version, Branch, PR, Commit และสถานะ ไม่มี Token หรือเนื้อหา Private Key
- การเปลี่ยนสถานะและการเขียน GitHub บันทึกใน Audit เดิม

API ใหม่: `POST /api/policy/publish` และ `POST /api/policy/publication/check` รับเฉพาะ `{ "version": "UUID จากการ Save" }` ไม่รับ Repository, Branch, Path, Token หรือค่าคะแนนใหม่ผ่านคำสั่ง Publish

การทดสอบอัตโนมัติใช้ GitHub API จำลองและฐานข้อมูลแยก ไม่ใช่การเผยแพร่หรือ Merge บน GitHub จริง รายงานการส่งงานต้องระบุแยกจากการทดสอบใช้งานจริงเสมอ

อ้างอิง: [GitHub App installation tokens และการจำกัด Repository/Permissions](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app), [API สำหรับเปลี่ยนไฟล์ Repository](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents)
