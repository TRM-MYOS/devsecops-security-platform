# Apply เกณฑ์คะแนนจาก Dashboard เข้า Central โดยตรง

1. Super User เปิด Security Policy กรอก Minimum passing score จำนวนเต็ม 0–100 แล้วกด **Apply policy** และยืนยัน
2. ระบบบันทึก Version และเกณฑ์ใน SQLite แล้วใช้ GitHub App ส่ง Commit เปลี่ยนเฉพาะ `security-policy.yaml` บน Central `main` โดยตรง **ไม่สร้าง Branch หรือ PR และไม่ Merge PR ให้**
3. ระบบอ่าน Version และ Minimum score กลับจาก Central ก่อนแสดง Published / Awaiting report
4. งานสแกนรอบใหม่ที่โหลด Central รุ่นนี้ใช้เกณฑ์ใหม่ งานที่เริ่มไปแล้วอาจใช้ checkout เดิม ต้องตรวจ Policy version ของแต่ละ Run
5. เมื่อ Sync รายงานที่ยืนยันแหล่งที่มาแล้วและ Version/เกณฑ์ตรงกัน จะแสดง Observed in report ซึ่งยืนยันรายงานนั้น ไม่ได้รับรองว่าทุก Run ใช้เวอร์ชันเดียวกัน

Backend เชื่อมออก GitHub เท่านั้น ไม่ต้องเปิดรับ Connection จากอินเทอร์เน็ต Runner ไม่ต้องติดต่อ SQLite หรือเครื่อง Dashboard ไม่ต้องใช้ PAT หรือสร้าง Policy signing key สำหรับวิธีนี้

## ตั้งค่าครั้งแรก

- เผยแพร่โค้ด Central ที่รองรับ Policy version และรายงานก่อน ปุ่ม Apply ไม่เผยแพร่ Python หรือ Workflow ให้
- App/Installation จาก Owner Settings ต้องเข้าถึง `TRM-MYOS/devsecops-security-platform` พร้อม **Contents: Read and write** ส่วน Monitoring ยังคงใช้ Actions/Contents/Metadata read
- Publisher ขอ Token แยก จำกัด Repository เฉพาะ Central และขอ Contents write เท่านั้น ไม่ขอ Pull requests, Workflows หรือ Administration write
- กฎของ Central `main` ต้องอนุญาต App เขียนตรง หากบังคับ PR หรือปฏิเสธการเขียน ระบบแจ้งข้อผิดพลาด ไม่ปรับกฎ ไม่ใช้ Force และไม่ข้าม Protection
- คง Required Check และกฎป้องกัน Merge ของ Repository เป้าหมายตามเดิม
- หากมี `security-policy-source.json` บน Backend หรือ Central ต้องตรวจทานแหล่ง Policy ก่อน ระบบปฏิเสธ Repository apply เมื่อมี HTTPS source เพื่อไม่อ้างว่า YAML มีผลทั้งที่ Runner อ่านแหล่งอื่น

GitHub Contents token ไม่จำกัดเป็นรายไฟล์ การจำกัด Path อยู่ใน Backend ด้วย จึงต้องเก็บ App key ให้ปลอดภัย ผู้เรียก API เลือก Repository/Branch/Path เองไม่ได้ Trusted Central ยังถูกกำหนดในโค้ด ไม่เปลี่ยนตาม Target Owner อัตโนมัติ

## สถานะและการกู้คืน

| สถานะ | ความหมาย |
|---|---|
| Not applied | ค่ามีเฉพาะในเครื่องหรือยังไม่เคยส่ง ต้อง Apply |
| Published / Awaiting report | อ่านพบเกณฑ์และ Version บน Central ณ การตรวจล่าสุด รอรายงานใหม่ |
| Observed in report | เคยนำเข้ารายงานที่ใช้เกณฑ์และ Version นี้ ผลเก่ายังคง Policy เดิม |
| Publication failed | ยังไม่ยืนยัน Apply ตรวจสิทธิ์ เครือข่าย และ Conflict แล้ว Check GitHub status หรือ Retry apply เวอร์ชันเดิม |
| Superseded | Central เปลี่ยนไปใช้ Policy อื่น ต้องตรวจทานและ Save/Apply เวอร์ชันใหม่หากต้องการ |
| Legacy PR pending | PR รุ่นเก่ายังอยู่ ปิด PR ที่ไม่ต้องการด้วยตัวเอง อย่า Merge เกณฑ์เก่าหลัง Apply ใหม่ |

ถ้าถูกปฏิเสธก่อนเขียน Policy เดิมจะยังอยู่ แต่ **Timeout อาจเกิดหลัง GitHub รับ Commit แล้ว** อย่าถือว่าความล้มเหลวทุกกรณีหมายถึง Central ไม่เปลี่ยน ให้ Check หรือ Retry เวอร์ชันเดิม ระบบอ่าน Version กลับเพื่อกู้สถานะและไม่ส่ง Commit ซ้ำเมื่อค่าตรงแล้ว

ระบบตรวจ Head ก่อนเขียน และส่ง SHA ของไฟล์เดิมให้ Contents API เพื่อไม่เขียนทับ Policy ที่แก้พร้อมกัน ถ้า Head เปลี่ยนระหว่างเตรียมจะหยุดให้ตรวจทาน หากมี Commit เกิดในช่วงหลังตรวจ Head GitHub จะอัปเดตเฉพาะไฟล์ Policy และรักษาไฟล์อื่น โดย SHA ของ Policy ยังต้องตรง การเขียน GitHub กับ SQLite ไม่ใช่ธุรกรรมเดียวกัน จึงต้องยืนยันผลและกู้คืนด้วย Version

ข้อมูล PR รุ่นเก่าใน SQLite ยังคงอยู่เพื่อ Audit/ลิงก์ ไม่สร้างหรือลบ PR ให้อัตโนมัติ **ปิด PR เก่าที่ไม่ต้องการก่อนใช้ Apply โดยตรง** เพื่อป้องกันการ Merge เกณฑ์เก่ากลับมาภายหลัง

## สิทธิ์และ API

- Apply, Retry และ Check เฉพาะ Super User ตรวจ Session/CSRF และตรวจสิทธิ์กับ Version ซ้ำก่อนเขียน GitHub
- Operator/Viewer อ่านได้ ไม่สามารถเรียก API เปลี่ยนค่า
- HIGH/CRITICAL ยัง BLOCK สูตร Score/Grade และผลสแกนเก่าไม่เปลี่ยน YAML ที่เสียยัง Fail-Closed
- ใช้ตาราง `policy_publications` เดิม เก็บ Version, เกณฑ์, Method, Commit, สถานะ และ Audit ไม่เก็บ Token หรือเนื้อหา Private Key ไม่ต้องล้างฐานข้อมูล
- `PATCH /api/policy` ยังคงบันทึก Version ในเครื่องเท่านั้น
- `POST /api/policy/publish` รับเฉพาะ Version ที่บันทึกแล้ว ส่งตรงเข้า Central; `POST /api/policy/publication/check` ตรวจโดยไม่เขียนไฟล์
- หน้าเว็บ Apply เรียก Save และ Publish ตามลำดับหลังยืนยันครั้งเดียว ถ้าส่งไม่สำเร็จจะระบุว่าบันทึกเฉพาะในเครื่อง ไม่ถือว่าเปิดใช้
- Signed HTTPS ที่ตั้งไว้ยังรองรับ ปุ่มระบุ Save signed policy และไม่ส่ง Commit เข้า Central

## ตรวจรับ

Tests ใช้ GitHub API จำลอง ฐานข้อมูลและ Key แยก ครอบคลุมขอบเขต 0/100, Role/CSRF, กดซ้ำ, Conflict, ปฏิเสธการเขียน, Timeout หลังเขียนและ Retry, Version ในรายงาน และผลเก่าไม่เปลี่ยน ไม่ใช่หลักฐานการส่ง Policy จริง

ทดสอบจริงแยก: ตรวจ Commit ว่าเปลี่ยนเฉพาะ Policy โดยไม่สร้าง PR → รัน Target ใหม่ → ตรวจ Version/Minimum score/Commit/Run ใน Artifact และ Dashboard → ตรวจ PR เป้าหมายว่า BLOCK ปิดกั้น Merge จริง

อ้างอิง: [GitHub App installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app), [Contents API](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents), [Branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
