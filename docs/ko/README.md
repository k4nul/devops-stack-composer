# DevOps Stack Composer 한국어 안내

[원문 README](../../README.md)에서 전체 운영 절차와 상세 문서 링크를 확인할 수 있습니다.

## 목적

DevOps Stack Composer는 하나의 선언형 애플리케이션 계약에서 Docker 빌드, Jenkins 전달 파이프라인, Kubernetes 배포 트리를 일관되게 생성하는 Python CLI입니다. 세 공개 템플릿을 복사하지 않고 잠긴 Git 커밋의 지원 인터페이스를 호출합니다. 현재 릴리스는 `v0.2.5`, 설정 API는 `devops-stack.io/v1alpha1`입니다.

## 빠른 시작

Python 3.10~3.12, Git, PowerShell 7, Docker와 Docker Buildx가 기본 구성에 필요합니다.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

devops-stack doctor --project .
devops-stack inspect --project examples/python-service
devops-stack generate --project examples/python-service
devops-stack generate --project examples/python-service --write
devops-stack validate --project examples/python-service
```

`generate`는 기본적으로 미리보기만 수행하며, 파일을 쓰려면 `--write`를 명시해야 합니다.

## 주요 기능

- 알 수 없는 필드를 거부하는 YAML 및 JSON Schema 검증
- Docker, Jenkins, Kubernetes 어댑터가 공유하는 정규화 모델
- 정확한 템플릿 커밋을 기록하는 소스 잠금과 캐시 해석
- 원자적이고 프로젝트 내부로 제한된 생성 파일 쓰기
- 사람용/JSON diff, provenance 설명, 진단 및 보고서
- 선택적 build-once 공급망 검증과 로컬 registry/kind 실행
- 이미지 digest 일치와 변조 탐지 가능한 실행·릴리스 증거 검증

## 설정과 안전

- 로컬 템플릿의 `HEAD`가 잠금 커밋과 다르면 업그레이드로 간주하지 않고 실패로 보고합니다.
- 정적 `generate`와 `validate`는 이미지를 push하지 않습니다. `execute`는 선택한 프로필에 따라 실제 로컬 리소스를 변경할 수 있으므로 실행 계획과 `--dry-run`을 먼저 검토하십시오.
- 설정에는 Secret 값이 아니라 Kubernetes Secret 이름·키와 Jenkins credential ID 같은 참조만 기록하십시오.
- 사용자 명령과 annotation은 그대로 신뢰되는 입력이므로 비밀 값을 넣지 마십시오.
- 보고서는 기본적으로 기존 파일을 덮어쓰지 않으며, 교체에는 `--force`가 필요합니다.

## 검증

```sh
make test
python3 -m compileall -q src tests examples/python-service
git diff --check
```

실제 `kind-e2e`나 릴리스 검증은 kind, kubectl, kubeconform, Syft, Trivy 등 해당 프로필의 필수 도구가 준비된 환경에서만 실행하고, 누락된 도구를 통과로 보고하지 마십시오.
