# cloud-audit — Roadmap

> Ostatnia aktualizacja: 2026-03-03
> Wersja roadmapy: 2.0 (po researchu konkurencji i rynku)

---

## Pozycjonowanie — dlaczego cloud-audit istnieje

### Krajobraz konkurencji (stan na marzec 2026)

| Narzędzie | Stars | Checków | Czas skanu | Remediation | Status |
|-----------|-------|---------|------------|-------------|--------|
| **Prowler** v5.18 | ~12.3k | 576 (AWS) + 162 (Azure) + 79 (GCP) | **4+ godzin** na dużym koncie | `--fix` auto-remediation + Prowler Studio AI | Aktywny, agresywny rozwój |
| **Checkov** v3.2 | ~8.5k | 2500+ | Szybki (IaC only) | Linki do Prisma Cloud docs | Aktywny, Palo Alto backing |
| **ScoutSuite** v5.14 | ~7.5k | ~200 | 45 min | **Brak** | **MARTWY** — brak releases >12 mies. |
| **Trivy** v0.60 | ~32.2k | ~517 (cloud) | Szybki | **Brak** dla cloud | Aktywny, kontener-first |
| **Steampipe** v2.3 | ~7k | SQL-based | Real-time | **Brak** | Aktywny, AGPL |
| **AWS Security Hub** | N/A | ~223 | Ciągły | Auto via SSM | Płatny po 30 dni trial |

### Luki rynkowe — co cloud-audit wypełnia

1. **ScoutSuite jest martwy, nic go nie zastąpiło.** Był go-to tool do szybkich, jednorazowych audytów z pięknym HTML raportem. Teraz ta nisza jest pusta.

2. **Prowler jest za wolny i za głośny.** 4 godziny + 500 findingów = alert fatigue. Statystyka: 59% cloud security teams dostaje 500+ alertów dziennie, 55% przyznaje się do **pominięcia krytycznych alertów** (Forrester/HelpNetSecurity).

3. **Żadne narzędzie nie stawia remediation na pierwszym miejscu.** Prowler mówi co jest źle. Checkov mówi co jest źle w IaC. Żadne nie daje copy-paste Terraform/CLI fix code.

4. **CIS compliance jest oczekiwany, ale setup jest skomplikowany.** Prowler/Steampipe wymagają konfiguracji. Tool który mapuje checki do CIS kontrolek i generuje raport compliance to wysoka wartość.

5. **Wbudowane narzędzia AWS kosztują.** Security Hub + Config Rules szybko rosną ceną. Darmowa alternatywa open source zawsze jest mile widziana.

### Pozycja cloud-audit

> **Fast, opinionated AWS security audit. Curated checks. Zero noise. Copy-paste fixes.**

cloud-audit **nie jest kolejnym Prowlerem**. To **duchowy następca ScoutSuite** — szybki, lekki, z pięknym raportem — ale z dodaną remediacją i CIS mappingiem, których ScoutSuite nigdy nie miał.

**Dla kogo:**
- Zespoły 1-10 osób bez dedykowanego security team
- DevOps/SRE robiący szybki audit przed deployem
- Consultanci (jak HAIT) robiący audyty dla klientów
- Firmy potrzebujące CIS compliance evidence bez Security Hub

### Filozofia produktu

1. **High-signal only** — czy atakujący to wykorzysta? Jeśli nie, check nie istnieje.
2. **Każdy finding = gotowa naprawa** — AWS CLI + Terraform HCL + link do docs. Copy-paste i gotowe.
3. **Raporty piękne i użyteczne** — dla inżyniera i dla szefa.
4. **Zero konfiguracji na start** — `pip install cloud-audit && cloud-audit scan` daje wartość od razu.
5. **12 sekund, nie 12 minut** — szybkość to feature.
6. **CIS mapping gratis** — każdy check zmapowany do CIS AWS Foundations Benchmark.

---

## Architektura docelowa (v1.0)

```
cloud-audit/
├── src/cloud_audit/
│   ├── cli.py                    # Typer CLI (scan, diff, list-checks, version)
│   ├── models.py                 # Finding (+Remediation +compliance_refs), CheckResult, ScanReport
│   ├── scanner.py                # Orchestrator z Rich progress
│   ├── config.py                 # .cloud-audit.yml parser
│   ├── baseline.py               # Suppress/baseline management
│   ├── providers/
│   │   ├── base.py               # BaseProvider ABC
│   │   └── aws/
│   │       ├── provider.py       # AWSProvider (boto3, regions, check loading)
│   │       └── checks/
│   │           ├── iam.py        # 6 checks
│   │           ├── s3.py         # 5 checks
│   │           ├── ec2.py        # 5 checks
│   │           ├── vpc.py        # 5 checks
│   │           ├── rds.py        # 4 checks
│   │           ├── eip.py        # 1 check
│   │           ├── cloudtrail.py # 3 checks
│   │           ├── kms.py        # 3 checks
│   │           ├── lambda_.py    # 3 checks
│   │           ├── guardduty.py  # 2 checks
│   │           ├── config_.py    # 2 checks
│   │           ├── ssm.py        # 2 checks
│   │           ├── secrets.py    # 2 checks
│   │           └── cloudwatch.py # 2 checks
│   └── reports/
│       ├── html.py               # Enhanced Jinja2 renderer
│       ├── sarif.py              # SARIF 2.1.0 output (GitHub integration)
│       ├── markdown.py           # Markdown report
│       └── templates/
│           └── report.html.j2    # Redesigned template
├── tests/
│   ├── unit/
│   │   ├── test_models.py
│   │   ├── test_scanner.py
│   │   ├── test_config.py
│   │   └── aws/
│   │       ├── test_iam.py       # moto-based
│   │       ├── test_s3.py
│   │       ├── test_ec2.py
│   │       └── ...
│   └── conftest.py               # Shared fixtures
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                # Lint + test + typecheck + docker
│   │   └── release.yml           # PyPI trusted publisher
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   ├── feature_request.yml
│   │   └── config.yml
│   └── pull_request_template.md
├── demo.tape                     # VHS terminal demo script
├── .cloud-audit.example.yml      # Example config
├── pyproject.toml
├── ROADMAP.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md
```

---

## Fazy rozwoju

### Faza 1: Launch (v0.1.0) — Z dysku na świat

**Cel:** Kod ląduje na GitHub i PyPI. Narzędzie jest instalowalne i daje wartość od razu. Nie czekamy na perfekcję.

**Czas: 1-2 sesje robocze (5-8h)**

#### 1.1 Przygotowanie repo
- [ ] `git init` + push na `gebalamariusz/cloud-audit`
- [ ] GitHub repo topics: `aws`, `security`, `cloud-security`, `audit`, `python`, `cli`, `devops`, `compliance`
- [ ] Issue templates (bug report, feature request)
- [ ] PR template
- [ ] CONTRIBUTING.md (krótki — jak dodać nowy check)

#### 1.2 README upgrade
- [ ] Badge row: PyPI version, Python versions, CI status, License, Downloads
- [ ] Terminal demo GIF (VHS lub asciinema → GIF via agg)
- [ ] Positioning statement: 1 zdanie dlaczego nie Prowler
- [ ] Sekcja "Why cloud-audit?" (4 bullet points: zero config, fast, beautiful, copy-paste fixes)
- [ ] Comparison table vs Prowler vs ScoutSuite (uczciwy)

#### 1.3 Pyproject.toml fixes
- [ ] Classifiers: dodać `Python :: 3.10`, `Typing :: Typed`, `Information Technology`
- [ ] Keywords: dodać `compliance`, `cis`, `scanner`

#### 1.4 CI upgrade
- [ ] Dodać `mypy` job do CI
- [ ] Dodać Python 3.10 do test matrix
- [ ] Dodać `release.yml` — PyPI trusted publisher (auto-publish on tag)

#### 1.5 Publish
- [ ] PyPI trusted publisher setup (pending publisher na pypi.org)
- [ ] `git tag v0.1.0` → GitHub Actions auto-publish
- [ ] Verify: `pip install cloud-audit && cloud-audit version` działa
- [ ] Test na prawdziwym koncie AWS
- [ ] Fix ewentualnych bugów

**Definition of Done:** `pip install cloud-audit && cloud-audit scan` daje raport na czystym koncie AWS.

---

### Faza 2: Remediation + CIS (v0.2.0) — Kluczowy wyróżnik

**Cel:** Każdy finding zawiera gotowy kod naprawy + mapowanie do CIS. To jest TO co odróżnia cloud-audit od wszystkiego innego na rynku.

**Czas: 2-3 tygodnie (10-15h)**

#### 2.1 Model Remediation
- [ ] Nowy model w `models.py`:
  ```python
  class Remediation(BaseModel):
      cli: str              # AWS CLI command (copy-paste ready)
      terraform: str        # Terraform HCL snippet
      doc_url: str          # Link do AWS docs
      effort: Effort        # LOW / MEDIUM / HIGH

  class Finding(BaseModel):
      # ... istniejące pola ...
      remediation: Remediation | None = None
      compliance_refs: list[str] = []  # ["CIS 1.5", "CIS 2.1.1", "SOC2 CC6.1"]
  ```
- [ ] Backward compatibility JSON output (remediation jest optional)

#### 2.2 Remediation content — wszystkie 17 istniejących checków
Każdy check dostaje:
- AWS CLI command (gotowy do wklejenia)
- Terraform HCL snippet (gotowy do dodania)
- Link do oficjalnej dokumentacji AWS
- CIS Benchmark reference (jeśli dotyczy)

| Check ID | CIS Ref | Remediation (skrót) |
|----------|---------|---------------------|
| aws-iam-001 | CIS 1.5 | `aws iam create-virtual-mfa-device` + terraform `aws_iam_virtual_mfa_device` |
| aws-iam-002 | CIS 1.4 | CLI + procedura organizacyjna |
| aws-iam-003 | CIS 1.14 | `aws iam create-access-key` → `delete-access-key` |
| aws-iam-004 | CIS 1.12 | `aws iam update-access-key --status Inactive` |
| aws-s3-001 | CIS 2.1.5 | `aws s3api put-public-access-block` + terraform |
| aws-s3-002 | CIS 2.1.1 | `aws s3api put-bucket-encryption` + terraform |
| aws-s3-003 | — | `aws s3api put-bucket-versioning` + terraform |
| aws-ec2-001 | — | `aws ec2 modify-image-attribute --launch-permission` |
| aws-ec2-002 | CIS 2.2.1 | Note: wymaga copy → encrypt → replace |
| aws-ec2-003 | — | `aws ec2 terminate-instances` (z ostrzeżeniem) |
| aws-vpc-001 | CIS 5.3 | `aws ec2 delete-default-vpc` (z ostrzeżeniem) |
| aws-vpc-002 | CIS 5.2 | `aws ec2 revoke-security-group-ingress` + terraform |
| aws-vpc-003 | CIS 3.7 | `aws ec2 create-flow-logs` + terraform `aws_flow_log` |
| aws-eip-001 | — | `aws ec2 release-address` |
| aws-rds-001 | — | `aws rds modify-db-instance --no-publicly-accessible` |
| aws-rds-002 | — | Note: wymaga re-create (snapshot → restore encrypted) |
| aws-rds-003 | — | `aws rds modify-db-instance --multi-az` |

#### 2.3 CLI: wyświetlanie remediation
- [ ] Flaga `--remediation` / `-R` — wyświetla CLI/Terraform fix per finding w konsoli
- [ ] Flaga `--export-fixes <path>` — generuje shell script:
  - `set -e` na górze
  - `# === DRY RUN MODE === Odkomentuj komendy po review ===`
  - Każda komenda zakomentowana (`# aws rds modify...`), z check ID i resource jako komentarz
  - User musi świadomie odkomentować — zero ryzyka przypadkowego wykonania

#### 2.4 HTML report — sekcja remediation
- [ ] Każdy finding ma rozwijany panel "How to fix"
- [ ] Syntax highlighting (CLI + HCL)
- [ ] Copy-to-clipboard button
- [ ] Sekcja "CIS Benchmark Coverage" na dole raportu

#### 2.5 Testy — razem z remediation (nie osobno!)
Pisz testy PER CHECK, nie "najpierw testy, potem remediation":
- [ ] `moto[all]` w dev dependencies
- [ ] `conftest.py`: fixture `mock_aws_provider()`
- [ ] Test pattern: PASS (prawidłowa konfiguracja → 0 findings) + FAIL (zła → finding z remediation)
- [ ] Testy dla 17 checków (minimum 1 PASS + 1 FAIL per check)
- [ ] Test CLI: `--remediation` output
- [ ] Test `--export-fixes`: generuje poprawny shell script
- [ ] Cel: 80%+ coverage

**Definition of Done:** Każdy finding ma remediation (CLI + Terraform + CIS ref). `pytest --cov` → 80%+. `--export-fixes` generuje script.

**Milestone marketingowy:** Blog post na haitmg.pl — "Why Security Scanners Fail: The Remediation Gap"

---

### Faza 3: Visibility & Detection (v0.3.0) — CloudTrail, GuardDuty, Config

**Cel:** Pokrycie "czy w ogóle widzisz co się dzieje w Twoim koncie?" — najważniejsze checki po podstawowym bezpieczeństwie.

**Czas: 2 tygodnie (8-12h)**

#### Nowe checki: 10

| Check ID | Serwis | Severity | Co sprawdza | CIS Ref |
|----------|--------|----------|-------------|---------|
| aws-ct-001 | CloudTrail | CRITICAL | CloudTrail enabled (multi-region) | CIS 3.1 |
| aws-ct-002 | CloudTrail | HIGH | Log file validation enabled | CIS 3.2 |
| aws-ct-003 | CloudTrail | CRITICAL | CloudTrail S3 bucket not public | CIS 3.3 |
| aws-gd-001 | GuardDuty | HIGH | GuardDuty enabled | — |
| aws-gd-002 | GuardDuty | MEDIUM | Unresolved findings (>30 dni) | — |
| aws-cfg-001 | Config | MEDIUM | AWS Config enabled | — |
| aws-cfg-002 | Config | HIGH | Config recorder active (nie stopped) | — |
| aws-kms-001 | KMS | MEDIUM | KMS key rotation enabled | CIS 3.6 |
| aws-kms-002 | KMS | HIGH | KMS key bez `*` principal | — |
| aws-cw-001 | CloudWatch | HIGH | Root account usage alarm | CIS 4.3 |

#### Wymagania
- [ ] Każdy check od razu z remediation (CLI + Terraform + CIS ref)
- [ ] Każdy check z moto testem (PASS + FAIL)
- [ ] Aktualizacja README (check table)
- [ ] Aktualizacja HTML template (nowe kategorie)

**Razem po tej fazie: 27 checków**

**Definition of Done:** 10 nowych checków, wszystkie z remediation i testami. Raport pokazuje "Visibility & Detection" jako osobną kategorię.

**Milestone marketingowy:** Post na r/aws — "Your AWS account is blind: 3 services you need enabled yesterday"

---

### Faza 4: Compute & Secrets (v0.4.0) — Lambda, ECS, SSM, Secrets Manager

**Cel:** Pokrycie compute (serverless + containers) i zarządzania sekretami.

**Czas: 2-3 tygodnie (10-15h)**

#### Nowe checki: 10

| Check ID | Serwis | Severity | Co sprawdza |
|----------|--------|----------|-------------|
| aws-lambda-001 | Lambda | HIGH | Public Lambda function URL (bez auth) |
| aws-lambda-002 | Lambda | MEDIUM | Deprecated runtime (brak security patches) |
| aws-lambda-003 | Lambda | HIGH | Env vars z secrets pattern (API_KEY, PASSWORD, SECRET) |
| aws-ecs-001 | ECS | CRITICAL | Task definition w privileged mode |
| aws-ecs-002 | ECS | HIGH | Task bez logging (brak logConfiguration) |
| aws-ecs-003 | ECS | MEDIUM | ECS exec enabled (backdoor w prod) |
| aws-ssm-001 | SSM | MEDIUM | EC2 instances poza SSM |
| aws-ssm-002 | SSM | HIGH | SSM parameters bez SecureString |
| aws-sm-001 | Secrets Manager | MEDIUM | Secret nierotowany >90 dni |
| aws-sm-002 | Secrets Manager | LOW | Unused secret (koszt) |

#### Dodatkowe checki dla istniejących serwisów: 5

| Check ID | Serwis | Severity | Co sprawdza |
|----------|--------|----------|-------------|
| aws-iam-005 | IAM | CRITICAL | Overly permissive policy (`Action:*`, `Resource:*`) |
| aws-iam-006 | IAM | MEDIUM | Password policy za słaba |
| aws-ec2-004 | EC2 | HIGH | IMDSv1 enabled (SSRF → credential theft) |
| aws-s3-004 | S3 | LOW | S3 bez lifecycle policy (rosnące koszty) |
| aws-s3-005 | S3 | MEDIUM | S3 access logging disabled |

**Razem po tej fazie: 42 checki**

**Definition of Done:** 15 nowych checków, wszystkie z remediation + testy.

---

### Faza 5: CI/CD & Config (v0.5.0) — Narzędzie dla pipeline'ów

**Cel:** cloud-audit jako gate w CI/CD. Konfigurowalność dla powtarzalnych skanów. SARIF output dla GitHub Security tab.

**Czas: 2-3 tygodnie (10-15h)**

#### 5.1 SARIF output (GitHub integration)
- [ ] `--format sarif` — SARIF 2.1.0 output
- [ ] Mapowanie severity: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW → `note`
- [ ] `partialFingerprints` dla deduplikacji w GitHub
- [ ] Dokumentacja: jak podpiąć do `github/codeql-action/upload-sarif@v3`
- [ ] Użyć `sarif-pydantic` library (Pydantic models — pasuje do architektury)

#### 5.2 Config file (`.cloud-audit.yml`)
```yaml
provider: aws
profile: production
regions:
  - eu-central-1
  - eu-west-1
min_severity: medium
exclude_checks:
  - aws-ec2-003  # stopped instances — wiemy
suppressions:
  - check_id: aws-vpc-002
    resource_id: sg-0abc123
    reason: "VPN gateway — intentionally open"
    expires: 2026-06-01
```

#### 5.3 Baseline / Suppress
- [ ] `cloud-audit baseline create` → `.cloud-audit-baseline.json`
- [ ] `cloud-audit scan --baseline` → pokazuje TYLKO nowe findings
- [ ] "X findings suppressed" wyraźnie w raporcie

#### 5.4 CLI improvements
- [ ] `--min-severity <level>` — filtruj HIGH+CRITICAL only
- [ ] `--quiet` — exit code only (0=clean, 1=findings, 2=errors) — idealny do CI
- [ ] `--format json|html|markdown|sarif`
- [ ] `cloud-audit list-checks` — lista checków z metadata (severity, CIS ref, category)
- [ ] `--role-arn` — assume role (cross-account scanning)

#### 5.5 Remaining checks: 3

| Check ID | Serwis | Severity | Co sprawdza |
|----------|--------|----------|-------------|
| aws-ec2-005 | EC2 | LOW | Brak termination protection |
| aws-rds-004 | RDS | LOW | Auto minor upgrade disabled |
| aws-vpc-004 | VPC | MEDIUM | Unrestricted NACL (allow all inbound) |

**Razem po tej fazie: 45 checków**

**Definition of Done:** SARIF działa z GitHub Code Scanning. `.cloud-audit.yml` parsowany. `--quiet` exit codes. Cross-account via `--role-arn`.

**Milestone marketingowy:** GitHub Action `gebalamariusz/cloud-audit-action@v1` (prosty wrapper)

---

### Faza 6: Reports 2.0 + Launch (v1.0.0) — Executive-ready + Community

**Cel:** Raporty gotowe do wysłania klientowi consulting. Dokumentacja. Public launch.

**Czas: 3-4 tygodnie (15-20h)**

#### 6.1 Enhanced HTML report
- [ ] Executive summary na górze (1 paragraf, czytelny dla nie-technicznego):
  > "Your AWS account has 3 critical security issues. The most urgent: your RDS production database is publicly accessible from the internet."
- [ ] Findings grouped by priority: "Fix now" / "Fix this week" / "Plan for next sprint"
- [ ] CIS Benchmark compliance summary: X/37 controls passing
- [ ] Severity trend chart (jeśli baseline/previous scan)
- [ ] Responsive design + print-friendly CSS
- [ ] Logo customization (config: `report_logo: ./logo.png`)

#### 6.2 Diff / Compare
- [ ] `cloud-audit diff <old.json> <new.json>`:
  - Nowe findings, naprawione findings, zmiana score'u
  - "4 issues fixed, 2 new issues detected, score: 78 → 85 (+7)"
- [ ] Markdown output (idealny do paste w PR/Slack)

#### 6.3 Markdown report
- [ ] `--format markdown` — kompatybilny z GitHub rendering

#### 6.4 Dokumentacja
- [ ] README z demo GIF (aktualizacja z nowymi feature'ami)
- [ ] CHANGELOG.md (keepachangelog format)
- [ ] Check Reference — każdy check z opisem, severity, CIS ref, remediation
- [ ] CI/CD Integration Guide
- [ ] Contributing Guide (rozbudowany)

#### 6.5 Community setup
- [ ] Issue templates (bug, feature, new check proposal)
- [ ] Code of Conduct
- [ ] GitHub Discussions enabled
- [ ] Docker image na GHCR: `ghcr.io/gebalamariusz/cloud-audit:1.0.0`

#### 6.6 Launch sequence
1. Blog post na haitmg.pl: "cloud-audit 1.0 — fast, opinionated AWS security scanner"
2. Cross-post na dev.to (tags: `aws`, `python`, `security`, `opensource`)
3. **Show HN** — poniedziałek/wtorek, 8-10 AM EST
4. Reddit: r/aws, r/netsec, r/devops, r/Python, r/commandline
5. PR do awesome-lists:
   - `jassics/awesome-aws-security`
   - `toniblyx/my-arsenal-of-aws-security-tools`
   - `donnemartin/awesome-aws`
6. AlternativeTo.net — jako alternatywa do Prowler i ScoutSuite

**Razem: 45 checków, pełna remediation, CIS mapping, SARIF, piękne raporty**

**Definition of Done:** `pip install cloud-audit && cloud-audit scan` → profesjonalny raport z remediacją. 100 GitHub stars w ciągu 30 dni od launchu.

---

## Fazy opcjonalne (post v1.0)

### Faza 7 (opcjonalna): Ekspansja do ~60 checków

Dodatkowe checki dodawane organicznie na podstawie feedbacku:

| Check ID | Serwis | Severity | Co sprawdza |
|----------|--------|----------|-------------|
| aws-eks-001 | EKS | HIGH | Public API endpoint |
| aws-eks-002 | EKS | MEDIUM | Secrets bez KMS encryption |
| aws-eks-003 | EKS | MEDIUM | Outdated K8s version |
| aws-kms-003 | KMS | LOW | Unused KMS keys (koszt) |
| aws-vpc-005 | VPC | MEDIUM | VPC peering DNS resolution |
| aws-sns-001 | SNS | MEDIUM | Topic bez encryption |
| aws-cw-002 | CloudWatch | LOW | Brak billing alarm |
| + checki | na podstawie user feedback | — | — |

### Faza 8 (opcjonalna): Azure Provider

**Decyzja odroczona do post-v1.0.** Powody:
- Lepiej być nr 1 w jednym cloud niż średnim w dwóch
- Azure dodaje ogrom pracy (inne SDK, konwencje, testy)
- Dopiero po walidacji rynkowej AWS-only wersji
- Jeśli consulting klienci proszą o Azure — wtedy priorytet rośnie

Jeśli wejdzie: ~25 checków (Identity, Storage, VMs, NSG, Key Vault, SQL, AKS, Networking).

---

## Timeline

```
Faza 1 (v0.1.0) ──── Tydzień 1       ── Launch (GitHub + PyPI)
Faza 2 (v0.2.0) ──── Tydzień 2-4     ── Remediation + CIS + Testy ⭐
Faza 3 (v0.3.0) ──── Tydzień 5-6     ── Visibility (CloudTrail, GuardDuty, Config)
Faza 4 (v0.4.0) ──── Tydzień 7-9     ── Compute & Secrets (Lambda, ECS, SSM)
Faza 5 (v0.5.0) ──── Tydzień 10-12   ── CI/CD, SARIF, Config, Cross-account
Faza 6 (v1.0.0) ──── Tydzień 13-16   ── Reports 2.0 + Launch
```

**Łącznie do v1.0: ~4 miesiące** przy 5-10h/tydzień.

vs. poprzedni plan: 8 miesięcy. Skrócone o połowę przez:
- Wyrzucenie Azure z v1.0 (ogromny chunk pracy)
- Połączenie testów z remediation (nie osobno)
- Skupienie na 45 checków zamiast 52+25 (Azure)
- Eliminację fazy "testy osobno" — testy idą z każdym checkiem

---

## Priorytety: wartość vs effort

```
                    WARTOŚĆ
                      ▲
                      │
    Faza 2            │    Faza 6
    (Remediation      │    (Reports 2.0
     + CIS) ⭐         │     + Launch)
                      │
    ──────────────────┼─────────────────► EFFORT
                      │
    Faza 1            │    Faza 8
    (Ship it)         │    (Azure — post v1.0)
                      │
```

**Quick win:** Faza 1 — jeden wieczór, kod przestaje leżeć na dysku
**Biggest impact:** Faza 2 — remediation + CIS = zero konkurencji w tej niszy
**Growth play:** Faza 5-6 — SARIF + raporty + launch = GitHub stars + consulting leads
**Long game:** Faza 7-8 — więcej checków + Azure = na życzenie rynku

---

## Docelowa lista checków v1.0 (45)

### Legenda: 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🔵 LOW

### IAM (6)
- 🔴 `aws-iam-001` Root account MFA — CIS 1.5
- 🟠 `aws-iam-002` IAM users MFA — CIS 1.4
- 🟡 `aws-iam-003` Access key rotation >90 days — CIS 1.14
- 🟡 `aws-iam-004` Unused access keys >30 days — CIS 1.12
- 🔴 `aws-iam-005` Overly permissive IAM policy (`Action:*`, `Resource:*`)
- 🟡 `aws-iam-006` Password policy too weak — CIS 1.8

### S3 (5)
- 🟠 `aws-s3-001` Public S3 buckets — CIS 2.1.5
- 🟡 `aws-s3-002` S3 encryption at rest — CIS 2.1.1
- 🔵 `aws-s3-003` S3 versioning
- 🔵 `aws-s3-004` S3 bez lifecycle policy
- 🟡 `aws-s3-005` S3 access logging disabled

### EC2 (5)
- 🟠 `aws-ec2-001` Public AMIs
- 🟡 `aws-ec2-002` Unencrypted EBS — CIS 2.2.1
- 🔵 `aws-ec2-003` Stopped instances (koszt)
- 🟠 `aws-ec2-004` IMDSv1 enabled (SSRF risk)
- 🔵 `aws-ec2-005` Brak termination protection

### VPC (4)
- 🟡 `aws-vpc-001` Default VPC in use — CIS 5.3
- 🔴 `aws-vpc-002` Open security groups — CIS 5.2
- 🟡 `aws-vpc-003` VPC flow logs disabled — CIS 3.7
- 🟡 `aws-vpc-004` Unrestricted NACL

### RDS (4)
- 🔴 `aws-rds-001` Public RDS instances
- 🟠 `aws-rds-002` RDS encryption at rest
- 🟡 `aws-rds-003` RDS Multi-AZ disabled
- 🔵 `aws-rds-004` Auto minor upgrade disabled

### EIP (1)
- 🔵 `aws-eip-001` Unattached Elastic IPs

### CloudTrail (3)
- 🔴 `aws-ct-001` CloudTrail not enabled — CIS 3.1
- 🟠 `aws-ct-002` Log file validation disabled — CIS 3.2
- 🔴 `aws-ct-003` CloudTrail S3 bucket public — CIS 3.3

### KMS (2)
- 🟡 `aws-kms-001` Key rotation disabled — CIS 3.6
- 🟠 `aws-kms-002` Overly permissive key policy

### Lambda (3)
- 🟠 `aws-lambda-001` Public function URL
- 🟡 `aws-lambda-002` Deprecated runtime
- 🟠 `aws-lambda-003` Env vars z secrets

### ECS (3)
- 🔴 `aws-ecs-001` Task privileged mode
- 🟠 `aws-ecs-002` Task bez logging
- 🟡 `aws-ecs-003` ECS exec enabled

### GuardDuty (2)
- 🟠 `aws-gd-001` GuardDuty not enabled
- 🟡 `aws-gd-002` Unresolved findings

### AWS Config (2)
- 🟡 `aws-cfg-001` Config not enabled
- 🟠 `aws-cfg-002` Config recorder stopped

### SSM (2)
- 🟡 `aws-ssm-001` EC2 poza SSM
- 🟠 `aws-ssm-002` SSM parameters bez SecureString

### Secrets Manager (2)
- 🟡 `aws-sm-001` Secret nierotowany >90 dni
- 🔵 `aws-sm-002` Secret unused

### CloudWatch (1)
- 🟠 `aws-cw-001` No root account usage alarm — CIS 4.3

### Summary by severity
- 🔴 **CRITICAL:** 6 — te które atakujący exploituje w minutach
- 🟠 **HIGH:** 13 — poważne ryzyka, fix w ciągu tygodnia
- 🟡 **MEDIUM:** 16 — best practices, fix w ciągu miesiąca
- 🔵 **LOW:** 10 — koszt/reliability, nice to have

### CIS AWS Foundations Benchmark coverage
**16 z ~37 kontrolek CIS v3.0** — wystarczająco na "CIS-aligned" label w raporcie, nie na pełny compliance. Uczciwa komunikacja: "cloud-audit covers key CIS controls, not full benchmark".

---

## Synergia z HAIT consulting

### Scenariusz sprzedażowy (bez zmian — działa)
1. Potencjalny klient: "chcielibyśmy audyt AWS"
2. Mariusz: "Dam ci quick scan naszym narzędziem, za darmo. Oto raport."
3. Klient dostaje piękny HTML raport z 15 findingami i gotowymi fixami
4. Mariusz: "Widzisz te 3 CRITICAL? Mogę naprawić wszystko i dać Ci Terraform code w 2 tygodnie."
5. Klient kupuje — widzi konkretne problemy, nie abstrakcyjną "usługę audytu"

### Content pipeline (1 artykuł per faza)
| Faza | Artykuł | Cel |
|------|---------|-----|
| 1 | "Announcing cloud-audit — fast AWS security scanner" | Świadomość |
| 2 | "Why Security Scanners Fail: The Remediation Gap" | Thought leadership |
| 3 | "Your AWS Account Is Blind: 3 Services You Need Yesterday" | SEO + edukacja |
| 4 | "5 AWS Misconfigurations I Find in Every Audit" (listicle) | SEO + social |
| 5 | "How to Add AWS Security Scanning to Your GitHub Actions" | DevOps tutorial |
| 6 | "cloud-audit 1.0 — Show HN" | Launch |

Każdy artykuł: haitmg.pl → cross-post dev.to → odpowiedni subreddit.

### First 100 stars strategy
1. **Tydzień 1 (stars 0-30):** Personal outreach — byli koledzy, użytkownicy Terraform modułów, kontakty z branży
2. **Tydzień 2-4 (stars 30-70):** Blog post + odpowiadanie na pytania na r/aws i r/devops gdzie cloud-audit jest genuinely odpowiedzią
3. **Tydzień 5-8 (stars 70-100):** Show HN + awesome-lists PRs + release v0.2 z changelogiem

---

## Decyzje architektoniczne

### Dlaczego remediation-first (nie checks-first):
- Prowler ma 576 checków i ludzie **ignorują 90% z nich**
- 17 checków z gotowym Terraform fix > 100 checków z "enable encryption"
- Remediation to moment "aha, to narzędzie NAPRAWDĘ pomaga" — to jest word-of-mouth trigger

### Dlaczego CIS mapping od razu:
- SOC 2 + CIS to sweet spot dla małych zespołów
- 60-70% overlap między SOC 2, ISO 27001, PCI-DSS — CIS jest bazą
- Klienci consulting pytają "czy jesteśmy zgodni z CIS?" — to sprzedaje

### Dlaczego SARIF (nie tylko JSON/HTML):
- GitHub Code Scanning integration za darmo
- Findings pojawiają się w Security tab i PR annotations
- Differentiator — małe narzędzia nie mają SARIF. Prowler i Checkov mają.
- Implementacja: 2-3h z `sarif-pydantic` (Pydantic models — pasuje idealnie)

### Dlaczego NIE Azure w v1.0:
- Lepiej być nr 1 w jednym cloud niż średnim w dwóch
- Azure wymaga: azure-identity, azure-mgmt-*, inne konwencje, osobne testy, osobna dokumentacja
- Dopiero po walidacji: czy ktoś używa? Czy consulting klienci proszą o Azure?

### Dlaczego NIE plugin system:
- 45 kuratowanych checków > 200 community checków o różnej jakości
- Plugin system to premature abstraction — jeśli community urośnie, v2.0

### Dlaczego NIE SaaS:
- CLI tool = zero infrastruktury, zero maintenance, zero support burden
- Mariusz jest solo developer, nie startup founder
- SaaS = hosting + auth + billing + support + SLA + GDPR = nie teraz

---

## Metryki sukcesu

| Milestone | Metryka | Cel |
|-----------|---------|-----|
| Faza 1 | PyPI installs | >0 (tool istnieje na świecie) |
| Faza 2 | GitHub stars | 10+ (early adopters) |
| Faza 3 | Blog post views | 500+ (content traction) |
| Faza 6 | GitHub stars | 100+ w 30 dni od launch |
| Faza 6 | PyPI monthly downloads | 200+ |
| v1.0 + 3 mies. | Consulting lead z cloud-audit | 1+ klient |
| v1.0 + 6 mies. | GitHub stars | 500+ |
