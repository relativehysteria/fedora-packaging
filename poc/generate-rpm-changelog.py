#!/usr/bin/env python3

# TODO:
# * Remove all `NOTE: POC` code.
# * Figure out how to handle networking failures, including GitHub rate limits.
# * Figure out what should be done in the case of [fedora-all] bugs when an
#   update is released for a specific branch.
# * Are there any weird things like bugs depending on bugs depending on bugs..?

import sys
import re
import subprocess
import json
from os import getenv
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


# The user agent to use for all requests.
USER_AGENT = "podman-changelog-generator/1.0"

# How long to wait for HTTP endpoints before giving up.
HTTP_TIMEOUT = 20

# The Red Hat bugzilla endpoint.
BUGZILLA_URL = "https://bugzilla.redhat.com"

# The GitHub API endpoint.
GITHUB_API = "https://api.github.com"


def fetch(
    url: str,
    extra_headers: dict[str, str],
    timeout: int = HTTP_TIMEOUT,
    retries: int = 3,
) -> str:
    retries = max(retries, 0)

    headers={ "User-Agent": USER_AGENT }
    headers.update(extra_headers)
    request = Request(url, headers=headers)

    while True:
        retries -= 1
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode()
        except Exception as e:
            # TODO: Actually handle errors such as retry-after, etc.
            if retries < 0:
                raise e


# HEADING_RE: Markdown heading; #, ##, ###, etc.
# ADDRESSED_CVE_RE: The specific `* Addresses CVE-XXXX-XXXXX` line
HEADING_RE = re.compile(r"^\s*(#+)\s*(.*?)\s*#*\s*$")
ADDRESSED_CVE_RE = re.compile(r"^\s*[-*]\s+Addresses\s+\[?(CVE-\d{4}-\d+)\b")
def extract_cves(release_notes: str) -> list[str]:
    """Given `release_notes`, extracts the CVEs conforming to the format
    specified in https://github.com/podman-container-tools/podman/pull/30113"""
    cves = []
    security_level = None

    for line in release_notes.splitlines():
        heading = HEADING_RE.match(line)

        if heading:
            level = len(heading.group(1))
            title = heading.group(2).strip()

            # A heading at the same or higher level ends the current section.
            if security_level is not None and level <= security_level:
                security_level = None

            if security_level is None and title.casefold() == "security":
                security_level = level

            continue

        if security_level is not None:
            match = ADDRESSED_CVE_RE.match(line)
            if match:
                cves.append(match.group(1))

    # Remove duplicates while preserving order.
    return list(dict.fromkeys(cves))


def get_release_notes(git_org: str, git_repo: str, tag: str) -> str:
    """Fetch the release notes for `git_org/git_repo:tag` from GitHub."""
    # NOTE: POC
    return """### Security
- Addresses [CVE-2025-11395](https://github.com/podman-container-tools/container-libs/security/advisories/GHSA-3gcv-x57j-xqxv), where importing images containing crafted layer tarballs with the podman load command, or importing volumes containing crafted symlinks with podman volume import, allows overwriting files on the host.
* Addresses [CVE-2026-79699](https://github.com/podman-container-tools/container-libs/security/advisories/GHSA-mmq6-9mjh-hvq3), though we do not believe it is exploitable through the Podman command line.
* Addresses [CVE-2026-79705](./some_file_etc), likewise probbaly not exploitable through the Podman command line.
- CVE-2025-12345 -- without the 'Addresses prefix', won't be parsed.

### Misc
- Updated Buildah to v1.43.4
- Updated Common to v0.67.2
- Updated Image to v5.39.3
- Updated Storage to v1.62.1
- Addresses CVE-2025-12345 -- outside of the Security section, won't be parsed."""

    url = "{GITHUB_API}/repos/{git_org}/{git_repo}/releases/tags/{tag}"
    headers = { "Accept": "application/vnd.github+json" }
    release_data = json.loads(fetch(url, headers))
    return release_data.get("body") or ""


# XXX:
# component: How the fuck do we extract the component for container-libs?
# product: How about Fedora EPEL and other stuff?
def get_bugzilla_issues(
    cve: str,
    component: str,
    product: str = "Fedora"
) -> list[int]:
    """Find the Fedora tracking bug(s) for a full CVE identifier `cve`.

    Returns the IDs of the parent issue(s) and the package-specific
    tracking issue.
    """
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve):
        raise ValueError(f"Invalid CVE identifier: {cve}")

    # Search by summary rather than by CVE alias. Tracking bugs
    # generally have the CVE in their summary but don't have an alias.
    params = {
        "product": product,
        "component": component,
        "short_desc_type": "substring",
        "short_desc": cve,
        "include_fields": (
            "id,summary,product,component,blocks"
        ),
        "limit": 100,
    }

    url = f"{BUGZILLA_URL}/rest/bug?{urlencode(params)}"
    headers = { "Accept": "application/json" }
    data = json.loads(fetch(url, headers))
    bugs = data.get("bugs")

    if not isinstance(bugs, list):
        raise RuntimeError("Unexpected response from Bugzilla API")

    # Verify the search results rather than blindly trusting the API.
    cve_pattern = re.compile(rf"\b{re.escape(cve)}\b", re.IGNORECASE)

    def normalize_field(value) -> set[str]:
        """Normalize a Bugzilla field to a set of case-insensitive strings."""
        if isinstance(value, str):
            return {value.casefold()}

        if isinstance(value, (list, tuple, set)):
            return {
                item.casefold()
                for item in value
                if isinstance(item, str)
            }

        return set()

    matches = [
        bug for bug in bugs
        if product.casefold() in normalize_field(bug.get("product"))
        and component.casefold() in normalize_field(bug.get("component"))
        and cve_pattern.search(bug.get("summary", ""))
    ]

    if not matches:
        raise RuntimeError(
            f"No {product}/{component} tracking bug found for {cve}. "
            "Check Bugzilla visibility and search filters."
        )

    if len(matches) > 1:
        details = ", ".join(
            f"#{bug.get('id')}: {bug.get('summary')}"
            for bug in matches
        )
        raise RuntimeError(
            f"Multiple {componentt} tracking bugs "
            f"found for {cve}: {details}"
        )

    tracker = matches[0]
    tracker_id = int(tracker["id"])

    # Fedora tracking bugs block their parent CVE issue.
    # We can obtain the parent's numeric ID from this relationship
    # even when we cannot access the parent issue itself.
    parent_ids = [
        int(bug_id)
        for bug_id in tracker.get("blocks", [])
        if str(bug_id).isdigit() and int(bug_id) > 0
    ]

    # Include the parent first, followed by the actual package tracker.
    return list(dict.fromkeys(parent_ids + [tracker_id]))


def main():
    # NOTE: POC
    upstream_tag = "v5.8.7"
    # # Get the env vars
    # upstream_tag = getenv("PACKIT_PROJECT_UPSTREAM_TAG")
    # if not upstream_tag:
    #     raise ValueError("PACKIT_PROJECT_UPSTREAM_TAG not in env")

    # Parse the git organization (e.g. podman-container-tools) and the repo
    result = subprocess.run(
        ["git", "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        check=True,
    )
    git_origin = result.stdout.strip()

    # NOTE: POC
    git_origin = "https://github.com/podman-container-tools/podman.git"

    # We'll fetch the notes from the GitHub API.
    if "github" not in git_origin:
        raise ValueError(f"Not a GitHub upstream: f{git_origin}")

    if "://" not in git_origin and ":" in git_origin:
        path = git_origin.split(":", 1)[1]
    else:
        path = urlparse(git_origin).path

    parts = path.strip("/").removesuffix(".git").split("/")

    if len(parts) < 2:
        raise ValueError(f"Invalid Git remote URL: {git_origin}")

    git_org, git_repo = parts[:2]

    # Fetch the release notes for this release and parse out the CVEs.
    release_notes = get_release_notes(git_org, git_repo, upstream_tag)
    cves = extract_cves(release_notes)

    changelog_lines = []
    for cve in cves:
        # NOTE: POC, "podman" could also be buildah, containers-common, etc.
        bug_ids = get_bugzilla_issues(cve, "podman")

        changelog_lines.append(
            f"{cve}: "
            + ", ".join(f"fixes rhbz#{bug_id}" for bug_id in bug_ids),
        )

    version = upstream_tag.lstrip('v')
    print(f"- Update to {version} upstream release")
    for line in changelog_lines:
        print(f"- Addresses {line}")


if __name__ == "__main__":
    main()
