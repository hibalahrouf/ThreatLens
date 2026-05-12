"""
MASVS Audit Copilot — SBOM Scanner
Extracts dependencies from APK files and checks for known CVEs via OSV.dev API.
"""

import json
import zipfile
from io import BytesIO
from typing import List, Optional
from dataclasses import dataclass, field

import httpx


@dataclass
class Dependency:
    """A third-party dependency found in the APK."""
    name: str
    version: Optional[str] = None
    package_type: str = "maven"  # maven, npm, pypi, etc.
    license: Optional[str] = None


@dataclass
class VulnerableDependency:
    """A dependency with known CVEs."""
    dependency: Dependency
    cve_ids: List[str] = field(default_factory=list)
    severity: str = "medium"
    summary: str = ""
    osv_id: Optional[str] = None
    fixed_version: Optional[str] = None


def extract_dependencies_from_apk(file_data: bytes) -> List[Dependency]:
    """
    Extract third-party library dependencies from an APK file.

    Strategies:
    1. Parse META-INF/MANIFEST.MF for library info
    2. Search for build.gradle references in assets
    3. Detect known library fingerprints in DEX files

    Args:
        file_data: Raw APK file bytes.

    Returns:
        List of detected dependencies.
    """
    dependencies = []

    try:
        with zipfile.ZipFile(BytesIO(file_data)) as apk:
            file_list = apk.namelist()

            # Strategy 1: Parse POM files (maven dependencies embedded in APK)
            pom_files = [f for f in file_list if f.endswith("pom.xml") or f.endswith("pom.properties")]
            for pom_path in pom_files:
                try:
                    content = apk.read(pom_path).decode("utf-8", errors="ignore")
                    dep = _parse_pom_properties(content, pom_path)
                    if dep:
                        dependencies.append(dep)
                except Exception:
                    continue

            # Strategy 2: Detect known libraries from file patterns
            lib_patterns = {
                "okhttp": Dependency("com.squareup.okhttp3:okhttp", package_type="maven"),
                "retrofit": Dependency("com.squareup.retrofit2:retrofit", package_type="maven"),
                "gson": Dependency("com.google.code.gson:gson", package_type="maven"),
                "glide": Dependency("com.github.bumptech.glide:glide", package_type="maven"),
                "picasso": Dependency("com.squareup.picasso:picasso", package_type="maven"),
                "realm": Dependency("io.realm:realm-android-library", package_type="maven"),
                "firebase": Dependency("com.google.firebase:firebase-core", package_type="maven"),
                "sqlcipher": Dependency("net.zetetic:android-database-sqlcipher", package_type="maven"),
                "bouncycastle": Dependency("org.bouncycastle:bcprov-jdk15on", package_type="maven"),
                "apache.http": Dependency("org.apache.httpcomponents:httpclient", package_type="maven"),
            }

            joined_files = " ".join(file_list).lower()
            for pattern, dep in lib_patterns.items():
                if pattern in joined_files:
                    dependencies.append(dep)

            # Strategy 3: Check native libraries
            native_libs = [f for f in file_list if f.startswith("lib/") and f.endswith(".so")]
            for lib_path in native_libs:
                lib_name = lib_path.split("/")[-1].replace("lib", "").replace(".so", "")
                if lib_name and len(lib_name) > 2:
                    dependencies.append(
                        Dependency(name=f"native:{lib_name}", package_type="native")
                    )

    except zipfile.BadZipFile:
        pass

    return dependencies


def _parse_pom_properties(content: str, path: str) -> Optional[Dependency]:
    """Parse Maven pom.properties to extract group:artifact:version."""
    props = {}
    for line in content.strip().split("\n"):
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()

    group_id = props.get("groupId", "")
    artifact_id = props.get("artifactId", "")
    version = props.get("version", "")

    if group_id and artifact_id:
        return Dependency(
            name=f"{group_id}:{artifact_id}",
            version=version or None,
            package_type="maven",
        )
    return None


def check_osv_vulnerabilities(dependencies: List[Dependency]) -> List[VulnerableDependency]:
    """
    Check dependencies against the OSV.dev API for known CVEs.

    Args:
        dependencies: List of dependencies to check.

    Returns:
        List of vulnerable dependencies with CVE details.
    """
    vulnerable = []

    for dep in dependencies:
        if not dep.version or dep.package_type == "native":
            continue

        try:
            result = _query_osv(dep)
            if result:
                vulnerable.append(result)
        except Exception:
            continue

    return vulnerable


def _query_osv(dep: Dependency) -> Optional[VulnerableDependency]:
    """
    Query the OSV.dev API for a single dependency.

    Uses the OSV.dev batch query API:
    https://osv.dev/docs/
    """
    ecosystem_map = {
        "maven": "Maven",
        "npm": "npm",
        "pypi": "PyPI",
    }

    ecosystem = ecosystem_map.get(dep.package_type)
    if not ecosystem:
        return None

    payload = {
        "version": dep.version,
        "package": {
            "name": dep.name,
            "ecosystem": ecosystem,
        },
    }

    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(
                "https://api.osv.dev/v1/query",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        vulns = data.get("vulns", [])
        if not vulns:
            return None

        cve_ids = []
        summaries = []
        severities = []
        fixed_versions = []

        for vuln in vulns:
            # Extract CVE IDs
            for alias in vuln.get("aliases", []):
                if alias.startswith("CVE-"):
                    cve_ids.append(alias)

            summaries.append(vuln.get("summary", ""))

            # Extract severity
            for sev in vuln.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        score = float(score_str)
                        if score >= 9.0:
                            severities.append("critical")
                        elif score >= 7.0:
                            severities.append("high")
                        elif score >= 4.0:
                            severities.append("medium")
                        else:
                            severities.append("low")
                    except (ValueError, TypeError):
                        pass

            # Extract fix versions
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

        return VulnerableDependency(
            dependency=dep,
            cve_ids=list(set(cve_ids)),
            severity=severities[0] if severities else "medium",
            summary=summaries[0] if summaries else "Known vulnerability",
            osv_id=vulns[0].get("id"),
            fixed_version=fixed_versions[0] if fixed_versions else None,
        )

    except (httpx.HTTPError, KeyError):
        return None


def generate_cyclonedx_sbom(dependencies: List[Dependency]) -> dict:
    """
    Generate a CycloneDX SBOM JSON document.

    Args:
        dependencies: List of all detected dependencies.

    Returns:
        CycloneDX 1.5 JSON SBOM document.
    """
    components = []
    for dep in dependencies:
        component = {
            "type": "library",
            "name": dep.name,
            "version": dep.version or "unknown",
            "purl": _build_purl(dep),
        }
        if dep.license:
            component["licenses"] = [{"license": {"id": dep.license}}]
        components.append(component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": components,
    }


def _build_purl(dep: Dependency) -> str:
    """Build a Package URL (purl) for a dependency."""
    type_map = {"maven": "maven", "npm": "npm", "pypi": "pypi", "native": "generic"}
    purl_type = type_map.get(dep.package_type, "generic")

    if ":" in dep.name:
        group, artifact = dep.name.split(":", 1)
        return f"pkg:{purl_type}/{group}/{artifact}@{dep.version or 'unknown'}"
    return f"pkg:{purl_type}/{dep.name}@{dep.version or 'unknown'}"
