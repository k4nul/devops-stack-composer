"""Conservative application and existing DevOps file detection."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from devops_stack_composer.filesystem import project_root


@dataclass(frozen=True)
class RuntimeDetection:
    application_type: str | None
    language: str | None
    runtime: str | None
    confidence: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class InspectionResult:
    project_root: str
    runtime: RuntimeDetection
    build_command: str | None
    test_command: str | None
    run_command: str | None
    build_artifact: str | None
    port: int | None
    health_endpoint: str | None
    readiness_endpoint: str | None
    dockerfiles: tuple[str, ...]
    jenkinsfiles: tuple[str, ...]
    kubernetes_files: tuple[str, ...]
    conflicts: tuple[str, ...]
    missing: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["runtime"] = asdict(self.runtime)
        return value


TYPE_MARKERS = {
    "nodejs": ("package.json",),
    "python": ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
}

DEFAULTS = {
    "nodejs": {
        "language": "JavaScript/TypeScript",
        "runtime": "Node.js",
        "build": "npm ci && npm run build",
        "test": "npm test",
        "run": "npm start",
        "artifact": "dist",
        "port": 3000,
    },
    "python": {
        "language": "Python",
        "runtime": "Python 3",
        "build": "python -m compileall .",
        "test": "python -m unittest discover -s tests",
        "run": "python app.py",
        "artifact": ".",
        "port": 8000,
    },
    "java": {
        "language": "Java",
        "runtime": "JVM",
        "build": "./mvnw -B package",
        "test": "./mvnw -B test",
        "run": "java -jar target/app.jar",
        "artifact": "target/app.jar",
        "port": 8080,
    },
    "go": {
        "language": "Go",
        "runtime": "Go",
        "build": "go build -trimpath -o build/app ./...",
        "test": "go test ./...",
        "run": "./build/app",
        "artifact": "build/app",
        "port": 8080,
    },
    "rust": {
        "language": "Rust",
        "runtime": "native",
        "build": "cargo build --release --locked",
        "test": "cargo test --locked",
        "run": "./target/release/app",
        "artifact": "target/release/app",
        "port": 8080,
    },
    "static": {
        "language": "HTML/CSS/JavaScript",
        "runtime": "static web server",
        "build": "test -f index.html",
        "test": "test -f index.html",
        "run": "busybox httpd -f -p 8080",
        "artifact": ".",
        "port": 8080,
    },
}

IGNORED_PARTS = {".git", ".devops-stack", "generated", "generated-preview", ".venv", "node_modules"}


def _relative_files(root: Path, names: tuple[str, ...]) -> tuple[str, ...]:
    found: set[str] = set()
    for name in names:
        for path in root.rglob(name):
            if any(part in IGNORED_PARTS for part in path.relative_to(root).parts):
                continue
            if path.is_file():
                found.add(path.relative_to(root).as_posix())
    return tuple(sorted(found))


def _read_small(path: Path) -> str:
    try:
        if path.stat().st_size > 1024 * 1024:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _node_commands(root: Path) -> tuple[str, str, str, str]:
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        defaults = DEFAULTS["nodejs"]
        return defaults["build"], defaults["test"], defaults["run"], defaults["artifact"]
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    install = "npm ci" if (root / "package-lock.json").is_file() else "npm install --no-package-lock"
    build = f"{install} && npm run build" if "build" in scripts else install
    test = "npm test" if "test" in scripts else "npm exec --yes node --test"
    run = "npm start" if "start" in scripts else "node ."
    artifact = "dist" if "build" in scripts else "."
    return build, test, run, artifact


def _python_run_command(root: Path) -> str:
    candidates = ("app/server.py", "src/main.py", "app.py", "main.py")
    for candidate in candidates:
        if (root / candidate).is_file():
            return f"python {candidate}"
    return DEFAULTS["python"]["run"]


def _detected_ports(root: Path, files: tuple[str, ...]) -> tuple[int, ...]:
    patterns = (
        re.compile(r"\bEXPOSE\s+([0-9]{2,5})\b", re.IGNORECASE),
        re.compile(r"\b(?:PORT|port)\s*[:=]\s*[\"']?([0-9]{2,5})\b"),
        re.compile(r"\b(?:listen|serve_forever)\s*\(\s*[\"']?[^,)]*[\"']?\s*,?\s*([0-9]{2,5})"),
        re.compile(r"\btargetPort\s*:\s*([0-9]{2,5})\b"),
    )
    ports: set[int] = set()
    for relative in files:
        text = _read_small(root / relative)
        for pattern in patterns:
            for match in pattern.finditer(text):
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
    return tuple(sorted(ports))


def inspect_application(path: Path) -> InspectionResult:
    root = project_root(path)
    evidence_by_type: dict[str, list[str]] = {}
    for application_type, markers in TYPE_MARKERS.items():
        evidence = [marker for marker in markers if (root / marker).is_file()]
        if evidence:
            evidence_by_type[application_type] = evidence
    if not evidence_by_type and (root / "index.html").is_file():
        evidence_by_type["static"] = ["index.html"]

    ranked = sorted(evidence_by_type, key=lambda key: (-len(evidence_by_type[key]), key))
    application_type = ranked[0] if ranked else None
    conflicts: list[str] = []
    if len(ranked) > 1:
        conflicts.append("multiple application types detected: " + ", ".join(ranked))
    if application_type:
        defaults = DEFAULTS[application_type]
        runtime = RuntimeDetection(
            application_type=application_type,
            language=defaults["language"],
            runtime=defaults["runtime"],
            confidence="high" if len(evidence_by_type[application_type]) > 1 else "medium",
            evidence=tuple(evidence_by_type[application_type]),
        )
        if application_type == "nodejs":
            build_command, test_command, run_command, build_artifact = _node_commands(root)
        else:
            build_command = defaults["build"]
            test_command = defaults["test"]
            run_command = (
                _python_run_command(root)
                if application_type == "python"
                else defaults["run"]
            )
            build_artifact = defaults["artifact"]
    else:
        runtime = RuntimeDetection(None, None, None, "none", ())
        build_command = test_command = run_command = build_artifact = None

    dockerfiles = _relative_files(root, ("Dockerfile", "Dockerfile.*"))
    jenkinsfiles = _relative_files(root, ("Jenkinsfile", "*.Jenkinsfile"))
    yaml_files = _relative_files(root, ("*.yaml", "*.yml"))
    kubernetes_files = tuple(
        relative
        for relative in yaml_files
        if re.search(r"(?m)^kind:\s*(?:Deployment|Service|StatefulSet|Ingress|Namespace)\s*$", _read_small(root / relative))
    )
    candidate_files = tuple(sorted(set(dockerfiles + kubernetes_files + _relative_files(root, ("*.py", "*.js", "*.ts", "*.go", "*.rs", "*.java")))))
    detected_ports = _detected_ports(root, candidate_files)
    port = detected_ports[0] if detected_ports else (DEFAULTS[application_type]["port"] if application_type else None)
    if len(detected_ports) > 1:
        conflicts.append("multiple candidate ports detected: " + ", ".join(map(str, detected_ports)))

    combined_text = "\n".join(_read_small(root / relative) for relative in candidate_files)
    health = "/health" if "/health" in combined_text else None
    readiness = next(
        (endpoint for endpoint in ("/ready", "/readiness") if endpoint in combined_text),
        None,
    )
    if dockerfiles:
        conflicts.append("existing Dockerfile detected; init will select the existing strategy")
    if jenkinsfiles:
        conflicts.append("existing Jenkins pipeline detected; generated output will remain isolated")
    if kubernetes_files:
        conflicts.append("existing Kubernetes manifests detected; generated output will remain isolated")

    missing = []
    if not application_type:
        missing.append("application type")
    if health is None:
        missing.append("health endpoint")
    if readiness is None:
        missing.append("readiness endpoint")
    if port is None:
        missing.append("application port")

    return InspectionResult(
        project_root=str(root),
        runtime=runtime,
        build_command=build_command,
        test_command=test_command,
        run_command=run_command,
        build_artifact=build_artifact,
        port=port,
        health_endpoint=health,
        readiness_endpoint=readiness,
        dockerfiles=dockerfiles,
        jenkinsfiles=jenkinsfiles,
        kubernetes_files=kubernetes_files,
        conflicts=tuple(conflicts),
        missing=tuple(missing),
    )


def _repository_owner(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "config", "--get", "remote.origin.url"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return "change-me"
    remote = result.stdout.strip()
    if remote.startswith("git@") and ":" in remote:
        path = remote.split(":", 1)[1]
    else:
        path = urlparse(remote).path.lstrip("/")
    owner = path.split("/", 1)[0].lower() if "/" in path else "change-me"
    return re.sub(r"[^a-z0-9._-]", "-", owner).strip("-._") or "change-me"


def initial_config(inspection: InspectionResult) -> dict[str, Any]:
    if inspection.runtime.application_type is None:
        application_type = "python"
        defaults = DEFAULTS[application_type]
        inferred = "low: no language marker found; review all application commands"
    else:
        application_type = inspection.runtime.application_type
        defaults = DEFAULTS[application_type]
        inferred = (
            f"{inspection.runtime.confidence}: detected {application_type} from "
            + ", ".join(inspection.runtime.evidence)
        )
    root = Path(inspection.project_root)
    name = re.sub(r"[^a-z0-9-]", "-", root.name.lower().replace("_", "-")).strip("-")
    name = name[:63].rstrip("-") or "application"
    port = inspection.port or defaults["port"]
    health = inspection.health_endpoint or "/health"
    readiness = inspection.readiness_endpoint or "/ready"
    existing_dockerfile = inspection.dockerfiles[0] if inspection.dockerfiles else None
    dockerfile: dict[str, str] = {
        "strategy": "existing" if existing_dockerfile else "generated"
    }
    if existing_dockerfile:
        dockerfile["path"] = existing_dockerfile

    return {
        "apiVersion": "devops-stack.io/v1alpha1",
        "kind": "DevOpsStack",
        "metadata": {
            "name": name,
            "annotations": {
                "devops-stack.io/inference": inferred,
                "devops-stack.io/review-required": "true",
            },
        },
        "application": {
            "name": name,
            "serviceName": name,
            "type": application_type,
            "root": ".",
            "buildCommand": inspection.build_command or defaults["build"],
            "testCommand": inspection.test_command or defaults["test"],
            "runCommand": inspection.run_command or defaults["run"],
            "buildArtifact": inspection.build_artifact or defaults["artifact"],
        },
        "image": {
            "registry": "ghcr.io",
            "repository": f"{_repository_owner(root)}/{name}",
            "tag": {"strategy": "branch-sha"},
            "architectures": ["linux/amd64"],
        },
        "build": {
            "context": ".",
            "dockerfile": dockerfile,
            "multiStage": True,
            "reproducible": True,
            "cache": {"enabled": False, "from": [], "to": []},
        },
        "ci": {
            "jenkins": {"credentialId": "container-registry"},
            "branches": {
                "dev": ["develop", "feature/*"],
                "staging": ["staging", "release/*"],
                "production": ["main"],
            },
            "approval": {"production": True},
        },
        "environments": {
            "dev": {"namespace": f"{name}-dev", "environment": {"LOG_LEVEL": "debug"}},
            "staging": {"namespace": f"{name}-staging", "replicas": 2},
            "production": {
                "namespace": f"{name}-production",
                "replicas": 3,
                "resources": {
                    "requests": {"cpu": "250m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "512Mi"},
                },
            },
        },
        "deployment": {
            "namespace": name,
            "replicas": 1,
            "containerPort": port,
            "service": {"type": "ClusterIP", "port": 80},
            "health": {"path": health, "initialDelaySeconds": 5, "periodSeconds": 10},
            "readiness": {"path": readiness, "initialDelaySeconds": 2, "periodSeconds": 5},
            "environment": {"LOG_LEVEL": "info"},
            "secretRefs": [],
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "500m", "memory": "256Mi"},
            },
            "rollout": {"strategy": "RollingUpdate", "maxUnavailable": 0, "maxSurge": 1},
            "rollback": {"enabled": True, "revisionHistoryLimit": 10},
        },
        "supplyChain": {
            "sbom": {"enabled": True, "format": "spdx-json"},
            "provenance": {"enabled": True, "mode": "max"},
            "scan": {"enabled": True, "failOn": "high"},
        },
        "security": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": False,
            "seccompProfile": "RuntimeDefault",
            "serviceAccount": name,
        },
        "policies": {
            "production": {
                "minimumReplicas": 2,
                "requireApproval": True,
                "requireResourceLimits": True,
                "requireReadOnlyRootFilesystem": True,
            }
        },
    }
