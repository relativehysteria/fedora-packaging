#!/usr/bin/env python3

# TODO:
# * Remove all `NOTE: POC` code.
# * Figure out how to handle networking failures, including GitHub rate limits.
# * Figure out what should be done in the case of [fedora-all] bugs when an
#   update is released for a specific branch.

# Bugzilla lookup is best-effort:
# - Infrastructure/API failures are fatal.
# - Missing or ambiguous CVE-to-bug mappings are warnings.
# - Valid mappings are included even if other CVEs cannot be resolved.
#
# The goal is to automate as much of the changelog generation as
# possible without unnecessarily blocking an upstream release.

import argparse
import sys
import re
import subprocess
import json
from os import getenv
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


# The user agent to use for all requests.
USER_AGENT = "podman-changelog-generator/1.0"

# How long to wait for HTTP endpoints (in seconds) before giving up.
HTTP_TIMEOUT = 20

# The Red Hat bugzilla endpoint.
BUGZILLA_URL = "https://bugzilla.redhat.com"

# The GitHub API endpoint.
GITHUB_API = "https://api.github.com"


class BugzillaLookupError(Exception):
    """A Bugzilla issue could not be reliably associated with a CVE."""


def eprint(*args, **kwargs):
    """Wrapper around `print()` that uses stderr as its output."""
    print(*args, file=sys.stderr, **kwargs)


# TODO: Errors are not handled. Ok for POC; the final version MUST have a
# somewhat robust networking error handler.
def fetch(
    url: str,
    extra_headers: dict[str, str],
    timeout: int = HTTP_TIMEOUT,
    retries: int = 3,
) -> str:
    """Fetches data from a remote `url`, implementing a timeout and retries."""
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
    # NOTE: POC; this is the ~actual 6.2.0 podman changelog
    return """# Release Notes

## 6.2.0
### Security
- Addresses CVE-2026-121885, untrusted image labels could be used to trick podman auto-update into restarting incorrect systemd units [GHSA-55rm-rwr7-q2wr](https://github.com/podman-container-tools/podman/security/advisories/GHSA-55rm-rwr7-q2wr).
- Addresses CVE-2026-111361, malicious containers images could be able to bypass Digest and Signature validation [GHSA-pggw-qqjf-6cxw](https://github.com/podman-container-tools/container-libs/security/advisories/GHSA-pggw-qqjf-6cxw).
- Addresses CVE-2026-123876, default seccomp profile socket deny rule could be bypass by a malicious container.

### Features
- The `podman push` command now supports a new option, `--platform`, which selects and pushes a single platform-specific manifest instead of the entire list.
- The `podman kube play` command now supports a new option, `--validate`, which determines how unrecognized YAML fields are handled ([#18332](https://github.com/podman-container-tools/podman/issues/18332))."""

    # NOTE: POC; this is just a sample changelog to show what doesn't get parsed
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

    url = f"{GITHUB_API}/repos/{git_org}/{git_repo}/releases/tags/{tag}"
    headers = { "Accept": "application/vnd.github+json" }
    release_data = json.loads(fetch(url, headers))
    return release_data.get("body") or ""


# XXX: product: How about Fedora EPEL and other stuff?
def get_bugzilla_issues(
    cve: str,
    component: str,
    product: str = "Fedora",
) -> list[int]:
    """Find the Fedora tracking bug(s) for a full CVE identifier `cve` for
    `component` (such as podman, buildah, containers-common).

    Returns the IDs of the parent issue(s) and the package-specific
    tracking issue.

    NOTE: We intentionally only resolve direct parent relationships.
    More complicated Bugzilla dependency trees are not traversed.
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
        raise BugzillaLookupError(
            f"No {product}/{component} tracking bug found for {cve}."
        )

    if len(matches) > 1:
        details = ", ".join(
            f"#{bug.get('id')}: {bug.get('summary')}"
            for bug in matches
        )
        raise BugzillaLookupError(
            f"Multiple {component} tracking bugs found for {cve}: {details}"
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


def parse_env_and_args() -> argparse.Namespace:
    """Parses and validates the required env vars and program arguments."""
    # We require some Packit set env vars. Format of the dictionary here is:
    # { ENV_VAR: (argparse_namespace_variable, description) }
    required_env = {
        "PACKIT_PROJECT_VERSION": (
            "upstream_version",
            "Version that will be set in the RPM spec file.",
        ),
        "PACKIT_PROJECT_UPSTREAM_TAG": (
            "upstream_tag",
            "Upstream Git tag corresponding to the release.",
        ),
    }

    env_info = "Required environment variables (provided by Packit):\n"
    env_info += "\n".join(
        f"    {name}\n        {description}"
        for name, (_, description) in required_env.items()
    )

    description = "Generate RPM changelog entries from upstream release notes."

    # Parse the arguments passed to the program.
    parser = argparse.ArgumentParser(
        description=description,
        epilog=env_info,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--git-org", required=True,
        help="Upstream Git organization (e.g. podman-container-tools).")
    parser.add_argument("--git-repo", required=True,
        help="Upstream Git repository (e.g. podman).")
    parser.add_argument("--bugzilla-component",
        help="Bugzilla component to search for tracking bugs "
             "(default: same as git-repo).")

    # NOTE: I'm not quite sure we wanna filter by a specific product instead of
    # trying to do a catch-all or whatever.
    parser.add_argument("--bugzilla-product", default="Fedora",
        help="Bugzilla product to search for tracking bugs "
             "(default: Fedora).")

    args = parser.parse_args()

    # By default, the bugzilla component is the same as the repo.
    if args.bugzilla_component is None:
        args.bugzilla_component = args.git_repo

    # Error out on missing env vars.
    missing = [name for name in required_env if not getenv(name)]

    if missing:
        parser.error(
            "Missing required environment variables:\n"
            + "\n".join(f"  - {name}" for name in missing)
        )

    # Parse the env vars and save them to the parser namespace.
    for env_var, (attr, _) in required_env.items():
        setattr(args, attr, getenv(env_var))

    return args


def main():
    args = parse_env_and_args()

    # Fetch the release notes for this release and parse out the CVEs.
    release_notes = get_release_notes(
        args.git_org, args.git_repo, args.upstream_tag)
    cves = extract_cves(release_notes)

    # Fetch the issues for each CVE and generate a changelog line for them.
    changelog_lines = []
    warnings = []
    for cve in cves:
        try:
            bug_ids = get_bugzilla_issues(
                cve, args.bugzilla_component, args.bugzilla_product)
        except BugzillaLookupError as e:
            warnings.append(f"{cve}: {e}")
            continue

        fixes  = ", ".join(f"fixes rhbz#{bug_id}" for bug_id in bug_ids)
        changelog_lines.append(f"{cve}: {fixes}")

    # Print out the warnings for maintainers without aborting the whole update
    # process.
    # TODO: Verify that these warnings do actually show up somewhere. :D Though
    # it would be better if the maintainers were pinged instead of having to
    # check the upstream Packit output.
    if warnings:
        eprint("\nWARNING: Some CVEs could not be automatically associated "
               "with Fedora Bugzilla issues.")
        eprint("The downstream update will proceed without these CVE "
              "references.")
        eprint("Please inspect the following CVEs manually:")

        for warning in warnings:
            eprint(f"  - {warning}")

        eprint("\nPlease verify the corresponding Bugzilla issues before "
              "submitting the update.\n")

    eprint("Generated RPM changelog:")
    print(f"- Update to {args.upstream_version} upstream release")
    for line in changelog_lines:
        print(f"- Addresses {line}")


if __name__ == "__main__":
    main()
