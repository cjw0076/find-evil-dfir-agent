# Synthetic DFIR Trace (No-credential Demo)

## Purpose

- 실제 외부 SIFT/Protocol SIFT 연결 이전에 데모 구조를 검증한다.
- 블로커/증거 구조를 고정해, 계정 증빙 시점에 바로 실제 데이터로 대체 가능하게 만든다.

## Scenario

**Case ID:** `case-lab-01`

1. **01:02 UTC** — `ingestion` 이벤트 생성
   - Event: 다수 실패 로그인 시도
   - Source: `synthetic_syslog`
   - Severity: `medium`

2. **01:05 UTC** — `alert` 이벤트
   - Event: 관리 포트(22/tcp)에서 비정상 접속 패턴 7회 탐지
   - Severity: `high`
   - IOC: `198.51.100.77`, `usr_legacy_admin_reset`

3. **01:07 UTC** — `triage` 이벤트
   - 판단: 동일 출처 패턴 + 성공 없는 계정 열거 확인
   - 조치: 긴급 접근 차단, 계정 잠금 후보 목록 생성

4. **01:10 UTC** — `containment` 이벤트
   - 조치: 세션 만료, 임시 방화벽 규칙 강화
   - 상태: `triaging`

5. **01:15 UTC** — `verification` 이벤트
   - 검증: 재시도 트래픽 하락, 관리 계정 접근 이력 안정
   - 상태: `verified`

## Evidence-ledger fields used

- `evidence_id`
- `case_id`
- `event_time_utc`
- `event_type`
- `source`
- `summary`
- `severity`
- `owner`
- `status`
- `recommendation`
- `notes`

## Scripted output concept

1. 1분 데모: 알림 입력 → 정렬된 타임라인 표시 → 권장 조치 출력
2. 시각화: 이벤트 5개만 표시하는 단일 화면
3. 안전 조치: 합성 데이터임을 명시하고 원본 로그 미노출

## Limitation

- 현재는 synthetic-only 데모이며, `Protocol SIFT`/`splunk` 실연결 증거가 확보되면 동일 스키마를 실데이터로 교체한다.
