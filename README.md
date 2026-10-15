# DevSecOps Security Platform

ระบบกลางสำหรับตรวจความปลอดภัยของ GitHub repositories ด้วย Bandit, Trivy และ Gitleaks พร้อม Dashboard, ประวัติผลสแกน และบัญชีผู้ใช้ที่ตรวจสิทธิ์ผ่าน FastAPI

## เริ่มใช้งานบน Windows

ใช้ Python 3.13 และติดตั้ง Git, Trivy และ Gitleaks ให้เรียกได้จาก `PATH` ส่วน Bandit ติดตั้งผ่าน requirements อยู่แล้ว

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m auth.bootstrap --username admin
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --no-proxy-headers
```

คำสั่ง bootstrap ถามรหัสผ่านและยืนยันแบบไม่แสดงข้อความที่พิมพ์ ไม่มีรหัสผ่านเริ่มต้น Username ใช้ตัวอักษรอังกฤษ ตัวเลข `_`, `.`, `-` จำนวน 3–64 ตัว และรหัสผ่านต้องยาว 12–128 ตัวอักษร Bootstrap ใช้สร้าง Super User คนแรกเท่านั้นและไม่เขียนทับบัญชีที่มีอยู่

เปิด <http://127.0.0.1:8000/dashboard/login.html> แล้ว Login ด้วยบัญชีที่สร้าง หากมี `.venv` อยู่แล้ว สามารถใช้ `.\.venv\Scripts\python.exe` แทน `python` ได้โดยไม่ต้อง activate

ยังคงอนุญาตให้สแกนเฉพาะ GitHub repositories ของ **TRM-MYOS** ตามข้อจำกัดเดิม ไม่ต้อง Login สำหรับการเรียก scanner ผ่าน CLI หรือ GitHub Actions

## สิทธิ์ผู้ใช้

| การทำงาน | Viewer | Operator | Super User |
|---|---|---|---|
| ดู Dashboard, findings, history และ policy | ✓ | ✓ | ✓ |
| เพิ่ม repository และสแกนเดี่ยว/ทั้งหมด | — | ✓ | ✓ |
| ลบ repository | — | — | ✓ |
| สร้าง/เปิด/ปิดบัญชีและเปลี่ยน role | — | — | ✓ |
| ดู audit log การเปลี่ยนบัญชี/สิทธิ์ | — | — | ✓ |

Super User จัดการบัญชีผ่านหน้า **User Management** ไม่มีการสมัครบัญชีสาธารณะ การเปลี่ยน role หรือปิดบัญชีจะยกเลิก session ของบัญชีนั้น ผู้ใช้ต้อง Login ใหม่เพื่อใช้สิทธิ์ปัจจุบัน ระบบไม่อนุญาตให้ปิดบัญชีหรือลดสิทธิ์ Super User ที่ใช้งานได้คนสุดท้าย

## การตั้งค่า

แอปอ่าน environment variables ของ process โดยตรง `.env.example` เป็นตัวอย่างการตั้งค่าและ **ไม่ถูกโหลดอัตโนมัติ** ควรตั้งค่าก่อนรัน bootstrap หรือ Uvicorn ใช้ฐานข้อมูล path เดียวกันสำหรับทั้งสองคำสั่ง

| ตัวแปร | ค่าเริ่มต้น development | ความหมาย |
|---|---|---|
| `DEVSECOPS_ENV` | `development` | `development` หรือ `production` |
| `DEVSECOPS_DATABASE_PATH` | `devsecops.db` ใน root โปรเจกต์ | SQLite สำหรับข้อมูลเดิมและบัญชีผู้ใช้ |
| `DEVSECOPS_ALLOWED_ORIGINS` | `http://127.0.0.1:8000,http://localhost:8000` | Origins ที่อนุญาต คั่นด้วย comma ไม่มี wildcard หรือ slash ท้าย URL |
| `DEVSECOPS_COOKIE_SECURE` | `false` | ใน production ต้องเป็น `true` |
| `DEVSECOPS_SESSION_TTL_SECONDS` | `28800` | อายุ session 8 ชั่วโมง |
| `DEVSECOPS_LOGIN_MAX_ATTEMPTS` | `5` | จำนวนครั้งที่ลอง Login ได้ในช่วงเวลา |
| `DEVSECOPS_LOGIN_WINDOW_SECONDS` | `900` | ช่วงจำกัด Login 15 นาที |

ตัวอย่าง production หลังตั้ง HTTPS ผ่าน reverse proxy:

```powershell
$env:DEVSECOPS_ENV = 'production'
$env:DEVSECOPS_ALLOWED_ORIGINS = 'https://security.example.com'
$env:DEVSECOPS_COOKIE_SECURE = 'true'
$env:DEVSECOPS_DATABASE_PATH = 'C:\data\devsecops\platform.db'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

สร้างโฟลเดอร์ฐานข้อมูลก่อนเริ่มระบบและจำกัดสิทธิ์เข้าถึงไฟล์ SQLite เปิด HTTPS สำหรับผู้ใช้ภายนอกและตั้ง trusted proxy ให้ตรงกับ deployment จริง ห้ามเผยแพร่พอร์ต development โดยตรง ใช้ origins ของเว็บไซต์จริงเท่านั้น หากเปลี่ยนพอร์ต development ให้ปรับ `DEVSECOPS_ALLOWED_ORIGINS` ให้ตรงด้วย

การเพิ่มตารางบัญชีเป็นแบบ additive ไม่ลบ repositories, scans หรือ findings เดิม สำรองฐานข้อมูลก่อนนำเวอร์ชันใหม่ขึ้นระบบจริง

## API และ session

- `GET /health`: ตรวจว่า API ตอบสนอง ไม่ใช่การยืนยันว่าเครื่องมือ scanner ทั้งหมดพร้อม
- `GET /api/auth/csrf`: สร้าง anonymous session และส่ง CSRF token สำหรับ Login
- `POST /api/auth/login`: รับ `{username, password}` และหมุน session หลัง Login สำเร็จ
- `GET /api/auth/me`: ส่งข้อมูลผู้ใช้และ CSRF token ปัจจุบัน
- `POST /api/auth/logout`: ยกเลิก session
- `GET /api/policy`: อ่านนโยบายจาก YAML และเกณฑ์คะแนนจริง ผู้ใช้ที่ Login ทุก role อ่านได้
- `GET /api/users`, `POST /api/users`, `PATCH /api/users/{id}`: จัดการบัญชีสำหรับ Super User
- `GET /api/users/audit`: ประวัติการเปลี่ยนบัญชี/สิทธิ์สำหรับ Super User

Session cookie เป็น HttpOnly และ SameSite พร้อม Secure ใน production เก็บ password เป็น Argon2id hash และ session ID เป็น hash ในฐานข้อมูล API ที่เปลี่ยนข้อมูลต้องส่ง `X-CSRF-Token` และ session cookie ผู้ไม่ได้ Login ได้ HTTP 401 และผู้ไม่มีสิทธิ์ได้ HTTP 403 ไม่สามารถข้ามการตรวจสิทธิ์ด้วยการเปิด API โดยตรง

หน้า `/docs`, `/redoc` และ `/openapi.json` เปิดเฉพาะ development และถูกปิดใน production หากใช้ reverse proxy ให้กำหนด trusted proxy IPs ของ Uvicorn อย่างชัดเจน เพราะมีผลต่อ client IP ที่ใช้จำกัดการลอง Login

## การทดสอบ

```powershell
python -m pip check
python -m pytest -q
node --check dashboard/app.js
```

Tests ใช้ฐานข้อมูลชั่วคราวและ mock การสแกน ไม่แตะ `devsecops.db` จริง ครอบคลุม Login/Logout/expiry, CSRF, สิทธิ์แต่ละ role, session revocation, rate limiting, Super User คนสุดท้าย, migration และการคงพฤติกรรมคะแนน/ประวัติเดิม

TestClient ของ Starlette รุ่นปัจจุบันอาจแสดง deprecation warning สำหรับ `httpx` โดย tests ยังทำงานได้ ไลบรารีที่ติดตั้งใน requirements นี้เป็นชุดที่ตรวจสอบการทำงานร่วมกันแล้ว

สำหรับตรวจเว็บ ให้เปิดทั้ง desktop และ mobile ตรวจ Login/Logout, ทุกเมนู, empty/loading/error states และผลสแกน ALLOW/BLOCK การสแกนครบวงจรจริงต้องมีเครื่องมือบน PATH และ repository ที่อนุญาต
