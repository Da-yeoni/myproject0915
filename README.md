# 📝 메모 서비스 (Flask + SQLite)

로그인 기반 개인 메모 서비스.

- 단일 파일(`app.py`) 구성
- DB: SQLite (`memo.db`, 자동 생성)
- 화면: 순수 HTML

## 기능
- 회원가입 / 로그인 / 로그아웃 (세션 유지)
- 개인 메모: 작성 · 목록 · 상세 · 수정 · 삭제 (본인 것만)

## 실행
```powershell
pip install -r requirements.txt
python app.py
```
→ 브라우저에서 `http://127.0.0.1:5000` 접속

