# ALEPH XDR-02 · 웹 주입 공격 탐지

Wazuh 모양의 웹 접근 경보에서 **SQL 주입·스크립트 삽입·경로 탐색·명령 구분자** 공격 징후를 분석하고, MITRE ATT&CK **T1190**에 따라 `block`, `alert`, `record`로 구분하는 독립형 보너스 과제입니다.

[웹사이트에서 실습 결과 확인하기](https://sdy-xdr-02.vercel.app) · [기본 Vercel 도메인](https://aleph-xdr-02-web-injection.vercel.app)

> **시뮬레이션 범위:** 실제 Wazuh 서버, 기존 운영 ZTNA 판정기 또는 실서비스 네트워크 차단 장비는 연결되지 않았습니다. 원본에서 제공하는 **교육용 가상 웹 경보 26건**과 **파일 기반 ZTNA 모의 판정기**로 요구사항의 탐지·알림·임시 거부 흐름을 검증합니다. 사용자 비밀번호·비밀키 등 실제 비밀값은 사용하지 않습니다.

## 최종 제출 및 검증 정보

- **배포 주소:** https://sdy-xdr-02.vercel.app
- **GitHub 저장소:** https://github.com/sdydy0298-dotcom/ALEPH-XDR-02-Web-Injection
- **GitHub Actions:** 원본 경보 재생 → 21개 자동 테스트 → 다시 재생 → 웹 빌드 → 결과 파일 일치 검사
- **개인정보/비밀값:** 수업용 문서 IP 및 가상 계정만 사용, 실제 인증 토큰이나 비밀키 없음
- 실제 Vercel 배포 상태는 프로젝트의 **Production / READY**를 기준으로 확인합니다.

## 원본 경보와 판정 결과

- 원본: [ChoiTimo/aleph-defense-starter의 `xdr/fixtures/web-injection.json`](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/xdr/fixtures/web-injection.json), **변경 없이 사용**
- 원본 교육용 실행기: [`scripts/xdr-run.mjs`](https://github.com/ChoiTimo/aleph-defense-starter/blob/main/scripts/xdr-run.mjs), **변경 없이 사용**
- 공식 경보 스키마: `aleph.xdr.fixture.v1`
- 공식 결과 스키마: `aleph.xdr.result.v1`

| 구분 | 현재 자체 검증 | 기준 |
|---|---:|---|
| **BLOCK** | **8건** | 명확하고 반복되는 주입 징후 + 출발 IP + 높은 Wazuh 경보 수준 |
| **ALERT** | **9건** | 단발성·모호한 웹 요청, 경고만 기록 |
| **RECORD** | **9건** | 평범한 자료 조회·검색·로그아웃 |
| 정상 이벤트 오차단 | **0건** | 정상 요청은 로컬 ZTNA에서 허용 |

**위 숫자는 원본 공개 교육용 예시에 대한 자체 판정 결과이며, 비공개 심판 정답표와 일치함을 보증하는 수치는 아닙니다.**

## 실행 방법

```bash
npm run xdr:run -- web-injection
npm test
npm run build
```

`npm run xdr:run -- web-injection`은 먼저 공식 실행기를 호출하여 26건에 대해 `decide(alert)`를 실행하고 `xdr/web-injection/result.json`을 공식 규격으로 생성합니다. 이어서 **응답 모듈이** 별도로 알림과 임시 거부 규칙을 생성합니다.

`npm run xdr:judge -- web-injection`을 사용하면 공식 원본 실행기만 독립 실행할 수 있습니다.

## 제작 단계별 점검

| 제작 | 파일 | 확인 |
|---|---|---|
| 1 · 경보 읽기 | `xdr/web-injection/read-alerts.mjs` | 26건 → 26줄, 시각·IP·계정·규칙 수준·설명만 추출하고 비밀 문자열 마스킹 |
| 2 · 패턴 목록 | `xdr/web-injection/patterns.json` | SQL / Script / Traversal / Command / Mixed / 불확실한 요청에 대한 한 줄 T1190 근거 |
| 3 · 판단 모듈 | `xdr/web-injection/decide.mjs` | **import 없는 독립 파일**, 파일·네트워크 I/O 없음, 임계치대로 세 행동 중 하나 반환 |
| 4 · 알림과 차단 | `xdr/web-injection/respond.mjs` | 명확한 `block`만 경보 ID 포함 **15분짜리** 거부 규칙 생성, `alert`는 로그만 |
| 5 · 시험 실행 | `xdr/run.mjs`, `result.json` | 원본 26건 분류, 정상 오차단 0, 반복 실행 동일한 결과 |
| 제출 | `.github/workflows/check.yml` | 자동 재생 → 단위 테스트 → 재생 → 웹 빌드 → 저장된 결과와 실제 결과 비교 |

판정 확신도: **0.85 이상 block**, **0.50 이상 alert**, 미만 **record**. `reason`은 근거 패턴명 또는 정상 기록 이유를 한 줄로 기록합니다.

### 안전한 대응 방식

`decide.mjs`는 오직 입력 이벤트 하나를 평가합니다. 암호, 요청 헤더, 전체 웹 요청 본문을 로그에 남기지 않습니다.

`respond.mjs`는 동일 이벤트를 재평가해 임의로 위조한 BLOCK 결과가 정상 이벤트를 차단하지 않도록 방어합니다. 증거 경보 번호, 출발 IP, 생성 시각, **15분 만료 시각**만을 동적 정책으로 기록합니다. 기본 허용/거부 정책 파일 `ztna/rules.json`은 실행 과정에서 **읽기만 하고 수정하지 않습니다**.

`ztna/evaluate.mjs`가 기존 정책과 `xdr/temporary-deny.json`의 활성 거부 규칙을 함께 평가합니다. 모호한 경보와 정상 웹 요청은 기존 허용 정책에 따라 통과합니다.

### 대시보드 사용법

공개 페이지에서 공격·애매한 검색·일반 웹 조회 예시를 선택하면 **같은 `decide.mjs` 함수를 브라우저에서 다시 실행**하고 판정·확신도·근거 패턴과 시험용 ZTNA 접근 허용 여부를 확인할 수 있습니다. 전송 없이 브라우저 내부에서만 실행되며 외부 사용자의 IP를 차단하지 않습니다.

### 파일 구성

```text
scripts/xdr-run.mjs                 공식 교육용 실행기
xdr/fixtures/web-injection.json    공식 교육용 Wazuh 예시 26건
xdr/web-injection/
  read-alerts.mjs                  검사 전용 안전 로그 출력
  patterns.json                    T1190 패턴과 근거
  decide.mjs                       심판 독립 모듈
  respond.mjs                      알림·임시 차단 파일 연결
  result.json                      공식 aleph.xdr.result.v1
xdr/alerts.log                     block/alert 알림 17줄
xdr/temporary-deny.json            테스트용 만료 규칙 8개
ztna/{rules,check,evaluate}.*      로컬 ZTNA 실습용 기존정책 + 임시규칙
tests/                             자동 테스트
index.html,app.js,styles.css        사용자 이해를 위한 인터랙티브 대시보드
```

## 한계

공식 예시의 `url` 값에는 `doc-sql-chain` 등 **의도적으로 실제 공격 문자열을 넣지 않은 교육용 표식**이 포함돼 있습니다. 따라서 이 프로젝트는 Wazuh 규칙 설명과 MITRE 분류, 경보 수준, 반복 횟수를 결합해 판정합니다. 실제 서비스에 적용하려면 운영 Wazuh, 서버 측 방화벽/정책 저장소, NAT 공유 IP의 정상 사용자 보호, 수동 승인·예외·해제 정책이 추가로 필요합니다.
