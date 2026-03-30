#!/usr/bin/env python3
"""
gspread OAuth2 인증 설정 가이드

GCP Console에서 OAuth 클라이언트 ID를 생성하고,
credentials.json을 ~/.config/gspread/에 저장한 뒤 인증합니다.
"""

import json
import os
import sys
from pathlib import Path

GSPREAD_DIR = Path.home() / ".config" / "gspread"


def main():
    print("━━━ gspread OAuth2 인증 설정 ━━━\n")

    creds_path = GSPREAD_DIR / "credentials.json"

    if creds_path.exists():
        print(f"✓ credentials.json 존재: {creds_path}")
    else:
        print("credentials.json이 없습니다.\n")
        print("GCP Console에서 OAuth 클라이언트 ID를 생성하세요:")
        print("  1. https://console.cloud.google.com/apis/credentials 접속")
        print("  2. '+ CREATE CREDENTIALS' > 'OAuth client ID' 선택")
        print("  3. Application type: 'Desktop app'")
        print("  4. 생성 후 JSON 다운로드")
        print(f"  5. 다운로드한 파일을 {creds_path} 으로 복사\n")
        print("또는 기존 OAuth JSON 파일 경로를 입력하세요 (없으면 Enter):")

        try:
            user_path = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n취소됨.")
            sys.exit(1)

        if user_path:
            src = Path(user_path).expanduser()
            if src.exists():
                GSPREAD_DIR.mkdir(parents=True, exist_ok=True)
                import shutil
                shutil.copy2(src, creds_path)
                print(f"\n✓ 복사 완료: {creds_path}")
            else:
                print(f"파일 없음: {src}")
                sys.exit(1)
        else:
            print("\ncredentials.json 없이는 OAuth2 인증을 진행할 수 없습니다.")
            print("\n대안: GCP 서비스 계정 사용")
            print("  1. GCP Console > IAM & Admin > Service Accounts")
            print("  2. 서비스 계정 생성 > JSON 키 다운로드")
            print("  3. Google Sheets에서 서비스 계정 이메일로 시트 공유")
            print("  4. GOOGLE_APPLICATION_CREDENTIALS=<path> 환경변수 설정")
            sys.exit(1)

    # Google Sheets API + Drive API 활성화 확인
    print("\n다음 API가 GCP 프로젝트에서 활성화되어 있어야 합니다:")
    print("  - Google Sheets API")
    print("  - Google Drive API")

    # 인증 실행
    print("\nOAuth2 인증을 시작합니다... (브라우저가 열립니다)")
    import gspread
    gc = gspread.oauth(
        scopes=[
            "https://www.googleapis.com/auth/spreadsheets.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
        ]
    )
    print("✓ 인증 성공!")

    # 테스트: 자산관리대장 접근 (환경변수에서 Sheet ID 로드)
    from pathlib import Path as _P
    _env = {}
    for _ep in [_P(os.environ.get("CLAUDESEC_ENV_FILE", "")), _P.cwd() / ".env", _P.home() / "Desktop" / ".env"]:
        if _ep.exists():
            for _ln in _ep.read_text().splitlines():
                if "=" in _ln and not _ln.startswith("#"):
                    _k, _v = _ln.split("=", 1)
                    _env[_k.strip()] = _v.strip()
            break

    asset_id = _env.get("ASSET_SHEET_ID", "")
    ai_id = _env.get("AI_SHEET_ID", "")

    if asset_id:
        try:
            sp = gc.open_by_key(asset_id)
            print(f"✓ 자산관리대장 접근 확인: '{sp.title}'")
        except Exception as e:
            print(f"✗ 자산관리대장 접근 실패: {e}")
    else:
        print("  ⚠ ASSET_SHEET_ID 미설정 — .env에 추가 필요")

    if ai_id:
        try:
            sp2 = gc.open_by_key(ai_id)
            print(f"✓ AI 구독 현황 접근 확인: '{sp2.title}'")
        except Exception as e:
            print(f"✗ AI 구독 현황 접근 실패: {e}")
    else:
        print("  ⚠ AI_SHEET_ID 미설정 — .env에 추가 필요")

    print("\n━━━ 설정 완료! ━━━")
    print("이제 다음 명령어로 전체 동기화를 실행할 수 있습니다:")
    print("  python3 scripts/sync-cost-xlsx.py --inject-html")


if __name__ == "__main__":
    main()
