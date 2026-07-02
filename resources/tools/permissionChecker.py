#!/usr/bin/env python3
"""
Android Manifest Permission Security Checker
=============================================
Analyzes AndroidManifest.xml files for common permission misconfigurations:
1. Missing protectionLevel on custom permissions
2. Typos in permission names (permission used by component not matching any <permission> declaration)
3. Typos in component declarations (android:uses-permission instead of android:permission)
4. Ecosystem mistakes (components protected by permissions not declared on the device)
5. readPermission/writePermission gaps on exported ContentProviders
"""

import xml.etree.ElementTree as ET
import subprocess
import sys
import os
import json
import difflib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

ANDROID_NS = "http://schemas.android.com/apk/res/android"
COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}

# System/vendor permission prefixes — these are not custom app permissions
# and should be skipped during permission misconfiguration checks
SYSTEM_PERMISSION_PREFIXES = (
    "android.permission.",
    "android.intent.",
    "android.provider.",
    "android.app.",
    "android.net.",
    "android.media.",
    "android.bluetooth.",
    "android.nfc.",
    "android.hardware.",
    "android.telephony.",
    "android.accounts.",
    "android.webkit.",
    "com.google.",
    "com.google.android.",
    "com.google.firebase.",
    "com.android.",
    "com.android.launcher.",
    "com.android.vending.",
    "com.android.browser.",
    "androidx.",
    "com.samsung.",
    "com.sec.",
    "com.huawei.",
    "com.xiaomi.",
    "com.miui.",
    "com.oppo.",
    "com.coloros.",
    "com.vivo.",
    "com.oneplus.",
    "com.realme.",
    "com.motorola.",
    "com.lge.",
    "com.sonyericsson.",
    "com.sony.",
    "com.asus.",
    "org.chromium.",
)

# Common standard Android permissions for reference
ANDROID_SYSTEM_PERMISSIONS = {
    "android.permission.ACCESS_CHECKIN_PROPERTIES",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_NOTIFICATION_POLICY",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.BROADCAST_STICKY",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.INTERNET",
    "android.permission.KILL_BACKGROUND_PROCESSES",
    "android.permission.MANAGE_OWN_CALLS",
    "android.permission.MODIFY_AUDIO_SETTINGS",
    "android.permission.NFC",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.SCHEDULE_EXACT_ALARM",
    "android.permission.SEND_SMS",
    "android.permission.SET_ALARM",
    "android.permission.SET_WALLPAPER",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.USE_BIOMETRIC",
    "android.permission.USE_FINGERPRINT",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.WRITE_SETTINGS",
}


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    check: str
    severity: str
    title: str
    description: str
    affected_component: str = ""
    permission: str = ""
    recommendation: str = ""
    attack_scenario: str = ""


@dataclass
class ManifestData:
    """Parsed manifest data used by all checks."""
    package: str
    tree: ET.ElementTree
    root: ET.Element
    declared_permissions: dict  # name -> {protectionLevel, element}
    used_permissions: set       # <uses-permission> names
    components: list            # [{tag, name, exported, permission, element, has_intent_filter, raw_attribs}]


# ─────────────────────────── Parsing ───────────────────────────

def parse_manifest(path: str) -> ManifestData:
    tree = ET.parse(path)
    root = tree.getroot()
    package = root.attrib.get("package", "")

    # Declared permissions
    declared = {}
    for perm in root.findall("permission"):
        name = perm.attrib.get(f"{{{ANDROID_NS}}}name", "")
        protection = perm.attrib.get(f"{{{ANDROID_NS}}}protectionLevel", None)
        declared[name] = {"protectionLevel": protection, "element": perm}

    # Uses-permissions
    used = set()
    for up in root.findall("uses-permission"):
        name = up.attrib.get(f"{{{ANDROID_NS}}}name", "")
        if name:
            used.add(name)

    # Components
    components = []
    app = root.find("application")
    if app is not None:
        for tag in COMPONENT_TAGS:
            for comp in app.findall(tag):
                attribs = comp.attrib
                name = attribs.get(f"{{{ANDROID_NS}}}name", "")
                exported_str = attribs.get(f"{{{ANDROID_NS}}}exported", None)
                permission = attribs.get(f"{{{ANDROID_NS}}}permission", None)
                has_intent_filter = comp.find("intent-filter") is not None

                # Determine effective exported value
                if exported_str is not None:
                    exported = exported_str.lower() == "true"
                else:
                    exported = has_intent_filter  # implicit export

                # Collect all raw attribute keys (without namespace) for typo detection
                raw_attribs = {}
                for k, v in attribs.items():
                    local = k.split("}")[-1] if "}" in k else k
                    raw_attribs[local] = v

                # Provider-specific: readPermission / writePermission
                read_permission = attribs.get(f"{{{ANDROID_NS}}}readPermission", None)
                write_permission = attribs.get(f"{{{ANDROID_NS}}}writePermission", None)

                components.append({
                    "tag": tag,
                    "name": name,
                    "exported": exported,
                    "exported_explicit": exported_str,
                    "permission": permission,
                    "readPermission": read_permission,
                    "writePermission": write_permission,
                    "has_intent_filter": has_intent_filter,
                    "element": comp,
                    "raw_attribs": raw_attribs,
                })

    return ManifestData(
        package=package,
        tree=tree,
        root=root,
        declared_permissions=declared,
        used_permissions=used,
        components=components,
    )


# ─────────────────────── Check 1: Missing protectionLevel ───────────────────────

def check_missing_protection_level(manifest: ManifestData) -> list[Finding]:
    """
    Custom permissions without an explicit protectionLevel default to 'normal',
    meaning ANY app can request and obtain them.
    """
    findings = []
    for perm_name, info in manifest.declared_permissions.items():
        if info["protectionLevel"] is None:
            # Find all exported components guarded by this permission
            guarded = [
                c for c in manifest.components
                if c["permission"] == perm_name and c["exported"]
            ]
            comp_details = ""
            if guarded:
                comp_list = ", ".join(
                    f'{c["tag"]} {c["name"]}' for c in guarded
                )
                comp_details = (
                    f" The following exported components are guarded by this permission "
                    f"and are therefore accessible to ANY third-party app: [{comp_list}]."
                )

            findings.append(Finding(
                check="Missing protectionLevel",
                severity=Severity.HIGH if guarded else Severity.MEDIUM,
                title=f"Custom permission '{perm_name}' has no protectionLevel (defaults to normal)",
                description=(
                    f"The <permission> declaration for '{perm_name}' does not specify "
                    f"android:protectionLevel. Android defaults this to 'normal', which means "
                    f"any application can request this permission and it will be granted "
                    f"automatically at install time without user confirmation.{comp_details}"
                ),
                affected_component=comp_details,
                permission=perm_name,
                recommendation=(
                    f'Add android:protectionLevel="signature" (or "dangerous") to the '
                    f"<permission> declaration for '{perm_name}'."
                ),
                attack_scenario=(
                    f"An attacker can create a malicious app with "
                    f'<uses-permission android:name="{perm_name}" /> and gain access to all '
                    f"components protected by this permission."
                ),
            ))
    return findings


# ─────────────────────── Check 2: Typos in permission names ───────────────────────

def check_permission_name_typos(manifest: ManifestData) -> list[Finding]:
    """
    Components reference a permission via android:permission that is NOT declared
    in <permission>. If the string is close to a declared permission, it's likely a typo.
    The undeclared permission defaults to normal -> any app can access the component.
    """
    findings = []
    declared_names = set(manifest.declared_permissions.keys())

    for comp in manifest.components:
        perm = comp["permission"]
        if perm is None or perm in declared_names:
            continue
        if perm in ANDROID_SYSTEM_PERMISSIONS:
            continue
        if any(perm.startswith(prefix) for prefix in SYSTEM_PERMISSION_PREFIXES):
            continue

        # Look for close matches among declared permissions
        close = difflib.get_close_matches(perm, declared_names, n=3, cutoff=0.6)
        close_detail = ""
        if close:
            matched = manifest.declared_permissions.get(close[0], {})
            matched_level = matched.get("protectionLevel", "not set")
            close_detail = (
                f" This looks like a typo — similar declared permission(s): {close}. "
                f"The declared permission '{close[0]}' has protectionLevel='{matched_level}', "
                f"but since '{perm}' is not declared, it defaults to normal."
            )

        if comp["exported"]:
            findings.append(Finding(
                check="Permission Name Typo",
                severity=Severity.HIGH,
                title=(
                    f"Component '{comp['name']}' uses undeclared permission '{perm}'"
                ),
                description=(
                    f"The {comp['tag']} '{comp['name']}' (exported={comp['exported']}) "
                    f"references permission '{perm}' via android:permission, but this "
                    f"permission is NOT declared with a <permission> tag in this manifest. "
                    f"Undeclared permissions default to protectionLevel='normal', making "
                    f"this component accessible to any app.{close_detail}"
                ),
                affected_component=f"{comp['tag']} {comp['name']}",
                permission=perm,
                recommendation=(
                    f"Verify the permission name. If it should match a declared permission, "
                    f"fix the typo. Otherwise, add a <permission> declaration with an "
                    f"appropriate protectionLevel."
                ),
                attack_scenario=(
                    f"A malicious app can add "
                    f'<uses-permission android:name="{perm}" /> '
                    f"to its manifest. Since '{perm}' is not declared anywhere, Android "
                    f"treats it as normal and grants it automatically, giving full access "
                    f"to {comp['tag']} '{comp['name']}'."
                ),
            ))
    return findings


# ──────────────── Check 3: Typos in component attribute names ────────────────

def check_component_attribute_typos(manifest: ManifestData) -> list[Finding]:
    """
    Detects when a component uses 'android:uses-permission' (or similar wrong attributes)
    instead of 'android:permission'. The component ends up with NO permission guard.
    """
    findings = []
    suspicious_attrs = {"uses-permission", "user-permission", "usepermission", "permision", "premission"}

    for comp in manifest.components:
        raw = comp["raw_attribs"]
        for attr_name, attr_val in raw.items():
            if attr_name.lower() in suspicious_attrs:
                findings.append(Finding(
                    check="Component Attribute Typo",
                    severity=Severity.CRITICAL if comp["exported"] else Severity.HIGH,
                    title=(
                        f"Component '{comp['name']}' uses incorrect attribute "
                        f"'android:{attr_name}' instead of 'android:permission'"
                    ),
                    description=(
                        f"The {comp['tag']} '{comp['name']}' (exported={comp['exported']}) "
                        f"has attribute 'android:{attr_name}=\"{attr_val}\"'. "
                        f"This is NOT a valid attribute for enforcing permission checks. "
                        f"The correct attribute is 'android:permission'. As a result, this "
                        f"component has NO permission protection and is accessible to any app."
                    ),
                    affected_component=f"{comp['tag']} {comp['name']}",
                    permission=attr_val,
                    recommendation=(
                        f"Replace 'android:{attr_name}' with 'android:permission' on "
                        f"component '{comp['name']}'."
                    ),
                    attack_scenario=(
                        f"Any third-party app can directly access {comp['tag']} "
                        f"'{comp['name']}' because the permission attribute is ignored by "
                        f"Android — the component is effectively unprotected."
                    ),
                ))
    return findings


# ──────────────── ADB: Fetch device-declared permissions ────────────────

# Prefixes to exclude (system / vendor permissions)
_ADB_EXCLUDE_PREFIXES = (
    "com.google.", "com.android.", "android.", "lineageos.", "org.lineageos.",
    "com.qualcomm.", "com.qti.", "org.codeaurora.", "androidx.",
)
_ADB_EXCLUDE_KEYWORDS = {"DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION", "C2D_MESSAGE"}


def fetch_device_permissions() -> set[str] | None:
    """
    Runs `adb shell pm list permissions -f` and returns the set of third-party
    custom permissions currently declared on the connected device.
    Returns None if adb is unavailable or no device is connected.
    """
    try:
        result = subprocess.run(
            ["adb", "shell", "pm list permissions -f"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    perms: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("+ permission:"):
            continue
        perm_name = line.split("+ permission:")[-1].strip()
        if not perm_name:
            continue
        # Apply the same exclusion filters
        if any(perm_name.startswith(prefix) for prefix in _ADB_EXCLUDE_PREFIXES):
            continue
        if any(kw in perm_name for kw in _ADB_EXCLUDE_KEYWORDS):
            continue
        perms.add(perm_name)
    return perms


# ──────────────── Check 4: Ecosystem permission issues ────────────────

def check_ecosystem_permission_issues(
    manifest: ManifestData,
    all_declared_permissions: set = None,
    device_permissions: set | None = None,
) -> list[Finding]:
    """
    Detects components protected by permissions not declared in this manifest.
    Verifies against device-installed permissions (via adb) when available.
    Only reports if the permission is NOT found on the device either.
    """
    findings = []
    declared_names = set(manifest.declared_permissions.keys())
    globally_declared = all_declared_permissions or declared_names

    for comp in manifest.components:
        perm = comp["permission"]
        if perm is None:
            continue
        if perm in ANDROID_SYSTEM_PERMISSIONS:
            continue
        if any(perm.startswith(prefix) for prefix in SYSTEM_PERMISSION_PREFIXES):
            continue
        if perm in declared_names:
            continue  # declared locally, safe
        if perm in globally_declared:
            continue  # declared in this manifest's own <permission> tags

        # Check if the permission exists on the device
        if device_permissions is not None and perm in device_permissions:
            continue  # another app on the device declares it, not vulnerable

        on_device_note = ""
        if device_permissions is not None:
            on_device_note = (
                " This permission was also NOT found among third-party permissions "
                "registered on the connected device (via adb), confirming that no "
                "installed app currently declares it."
            )
        elif device_permissions is None:
            on_device_note = (
                " (Could not verify against device — adb was unavailable. "
                "Run with a device connected to confirm.)"
            )

        perm_pkg = perm.rsplit(".", 1)[0] if "." in perm else ""
        is_foreign = not perm.startswith(manifest.package)

        if comp["exported"]:
            findings.append(Finding(
                check="Ecosystem Permission Issue",
                severity=Severity.HIGH,
                title=(
                    f"Component '{comp['name']}' protected by undeclared "
                    f"permission '{perm}'"
                ),
                description=(
                    f"The {comp['tag']} '{comp['name']}' (exported=true) is guarded by "
                    f"permission '{perm}', which is NOT declared (<permission>) in this "
                    f"manifest (package: {manifest.package}). "
                    f"{'This permission appears to belong to another app (' + perm_pkg + '). ' if is_foreign else ''}"
                    f"No app in the provided manifests declares this permission.{on_device_note} "
                    f"If no app on the device declares this permission, Android treats it "
                    f"as normal (protectionLevel=0x0), meaning ANY app can request and "
                    f"obtain it."
                ),
                affected_component=f"{comp['tag']} {comp['name']}",
                permission=perm,
                recommendation=(
                    f"Declare the permission in THIS manifest as well with the same "
                    f"protectionLevel, or use a permission that is locally declared. "
                    f"If the ecosystem requires a shared permission, both apps should "
                    f"declare it with <permission> and identical protectionLevel."
                ),
                attack_scenario=(
                    f"Attack Scenario 1 — Declare & Access: If the declaring app is not "
                    f"installed, an attacker app can simply add "
                    f'<uses-permission android:name="{perm}" /> and access '
                    f"{comp['tag']} '{comp['name']}' directly since the permission is "
                    f"treated as normal.\n"
                    f"Attack Scenario 2 — Hijack the Permission: The attacker app declares "
                    f"the permission itself with protectionLevel='normal': "
                    f'<permission android:name="{perm}" '
                    f'android:protectionLevel="normal" />, then requests it, effectively '
                    f"taking ownership of the permission definition and gaining full access "
                    f"to the component."
                ),
            ))
    return findings


# ──────────── Check 5: readPermission / writePermission gaps ────────────

def _get_protection_level(perm_name: str, manifest: ManifestData) -> str | None:
    """
    Returns the protectionLevel string for a permission declared in this manifest.
    Returns None if the permission is not declared locally.
    """
    info = manifest.declared_permissions.get(perm_name)
    if info is None:
        return None
    return info.get("protectionLevel")


def _is_strong_protection(level: str | None) -> bool:
    """True if the protectionLevel is signature-based (strong)."""
    if level is None:
        return False
    return any(kw in level.lower() for kw in ("signature",))


def _is_weak_protection(level: str | None) -> bool:
    """True if the protectionLevel is normal or missing (weak)."""
    if level is None:
        return True  # missing defaults to normal
    return level.lower() in ("normal", "0", "0x0", "0x00000000")


def check_provider_permission_gaps(manifest: ManifestData) -> list[Finding]:
    """
    Detects exported ContentProviders with readPermission/writePermission misconfigurations.

    Android's permission model for ContentProviders:
      - readPermission protects: query()
      - writePermission protects: insert(), update(), delete()
      - permission is the fallback for whichever specific permission is NOT set.
      - For file operations (openFile/openAssetFile), Android checks permissions based
        on the MODE parameter the caller passes ("r" → readPermission, "w" → writePermission),
        NOT what the provider's code actually does. So calling openFile(uri, "w") only checks
        writePermission, even if the provider returns a read-only file descriptor.

    Detected scenarios:
      Case 1: readPermission set, no writePermission, no permission
              → write ops + openFile("w") completely unprotected
      Case 2: writePermission set, no readPermission, no permission
              → read ops + openFile("r") completely unprotected
      Case 3: readPermission is STRONG (signature), no writePermission, permission is WEAK (normal)
              → openFile("w") only needs the weak fallback → bypasses strong read protection
      Case 4: writePermission is STRONG (signature), no readPermission, permission is WEAK (normal)
              → openFile("r") only needs the weak fallback → bypasses strong write protection
    """
    findings = []

    for comp in manifest.components:
        if comp["tag"] != "provider" or not comp["exported"]:
            continue

        read_perm = comp.get("readPermission")
        write_perm = comp.get("writePermission")
        base_perm = comp.get("permission")

        # Case 1: readPermission set, writePermission missing, no fallback permission
        if read_perm and not write_perm and not base_perm:
            findings.append(Finding(
                check="Provider Permission Gap",
                severity=Severity.HIGH,
                title=(
                    f"Provider '{comp['name']}' has readPermission but no writePermission "
                    f"— write operations and openFile(\"w\") are unprotected"
                ),
                description=(
                    f"The exported <provider> '{comp['name']}' declares "
                    f"android:readPermission=\"{read_perm}\" but does NOT declare "
                    f"android:writePermission or android:permission. "
                    f"In Android's ContentProvider permission model, readPermission only "
                    f"guards query() calls and openFile() with mode \"r\". Without a "
                    f"writePermission or a fallback permission attribute:\n"
                    f"  1) Write operations (insert, update, delete) are completely unprotected.\n"
                    f"  2) openFile(uri, \"w\") requires NO permission — Android checks "
                    f"writePermission for \"w\" mode, which is absent.\n"
                    f"Critically, the provider's openFile() implementation may ignore the mode "
                    f"and return a read-only file descriptor. So an attacker calling "
                    f"openFile(uri, \"w\") bypasses the readPermission check entirely and "
                    f"still gets read access to files."
                ),
                affected_component=f"provider {comp['name']}",
                permission=read_perm,
                recommendation=(
                    f"Add android:writePermission (or android:permission as a fallback) "
                    f"to the <provider> declaration for '{comp['name']}'. Ideally both "
                    f"readPermission and writePermission should be set explicitly, or use "
                    f"android:permission to cover both."
                ),
                attack_scenario=(
                    f"Attack 1 — Unprotected write operations:\n"
                    f"  ContentResolver cr = getContentResolver();\n"
                    f"  cr.insert(Uri.parse(\"content://<authority>/path\"), maliciousValues);\n"
                    f"  cr.delete(Uri.parse(\"content://<authority>/path\"), null, null);\n\n"
                    f"Attack 2 — openFile mode bypass (read files without readPermission):\n"
                    f"  Uri uri = Uri.parse(\"content://<authority>/data/data/com.victim/shared_prefs/secrets.xml\");\n"
                    f"  ParcelFileDescriptor pfd = getContentResolver().openFile(uri, \"w\", null);\n"
                    f"  InputStream is = new FileInputStream(pfd.getFileDescriptor());\n"
                    f"  // Read the file contents — provider returns read-only fd despite \"w\" mode"
                ),
            ))

        # Case 2: writePermission set, readPermission missing, no fallback permission
        if write_perm and not read_perm and not base_perm:
            findings.append(Finding(
                check="Provider Permission Gap",
                severity=Severity.HIGH,
                title=(
                    f"Provider '{comp['name']}' has writePermission but no readPermission "
                    f"— read operations and openFile(\"r\") are unprotected"
                ),
                description=(
                    f"The exported <provider> '{comp['name']}' declares "
                    f"android:writePermission=\"{write_perm}\" but does NOT declare "
                    f"android:readPermission or android:permission. "
                    f"In Android's ContentProvider permission model, writePermission only "
                    f"guards insert/update/delete calls and openFile() with mode \"w\". "
                    f"Without a readPermission or a fallback permission attribute:\n"
                    f"  1) query() is completely unprotected — any app can read data.\n"
                    f"  2) openFile(uri, \"r\") requires NO permission — Android checks "
                    f"readPermission for \"r\" mode, which is absent."
                ),
                affected_component=f"provider {comp['name']}",
                permission=write_perm,
                recommendation=(
                    f"Add android:readPermission (or android:permission as a fallback) "
                    f"to the <provider> declaration for '{comp['name']}'. Ideally both "
                    f"readPermission and writePermission should be set explicitly, or use "
                    f"android:permission to cover both."
                ),
                attack_scenario=(
                    f"Attack 1 — Unprotected read operations:\n"
                    f"  ContentResolver cr = getContentResolver();\n"
                    f"  Cursor c = cr.query(Uri.parse(\"content://<authority>/path\"), "
                    f"null, null, null, null);\n"
                    f"  // Iterate cursor to read all exposed data\n\n"
                    f"Attack 2 — openFile read access without any permission:\n"
                    f"  Uri uri = Uri.parse(\"content://<authority>/data/data/com.victim/files/sensitive.db\");\n"
                    f"  ParcelFileDescriptor pfd = getContentResolver().openFile(uri, \"r\", null);\n"
                    f"  InputStream is = new FileInputStream(pfd.getFileDescriptor());\n"
                    f"  // Read file contents without holding any permission"
                ),
            ))

        # Case 3: readPermission is STRONG, no writePermission, fallback permission is WEAK
        # The developer intended reads to be signature-protected, but openFile("w") only
        # needs the weak fallback → attacker bypasses strong read protection.
        if (read_perm and not write_perm and base_perm
                and read_perm != base_perm):
            read_level = _get_protection_level(read_perm, manifest)
            base_level = _get_protection_level(base_perm, manifest)
            if _is_strong_protection(read_level) and _is_weak_protection(base_level):
                findings.append(Finding(
                    check="Provider Permission Gap",
                    severity=Severity.HIGH,
                    title=(
                        f"Provider '{comp['name']}' — readPermission is signature-level but "
                        f"openFile(\"w\") only requires weak fallback permission"
                    ),
                    description=(
                        f"The exported <provider> '{comp['name']}' declares:\n"
                        f"  android:readPermission=\"{read_perm}\" "
                        f"(protectionLevel={read_level or 'signature'})\n"
                        f"  android:permission=\"{base_perm}\" "
                        f"(protectionLevel={base_level or 'normal (default)'})\n"
                        f"  No android:writePermission is set.\n\n"
                        f"For file operations, Android checks permissions based on the caller's "
                        f"requested mode: openFile(uri, \"r\") checks readPermission (signature), "
                        f"but openFile(uri, \"w\") checks writePermission — which is absent, so "
                        f"it falls back to android:permission (\"{base_perm}\", which is "
                        f"protectionLevel={base_level or 'normal'}).\n\n"
                        f"The provider's openFile() implementation may ignore the mode parameter "
                        f"and return a read-only file descriptor regardless. So an attacker "
                        f"holding only \"{base_perm}\" (a normal/weak permission) can call "
                        f"openFile(uri, \"w\") and still read files — completely bypassing the "
                        f"signature-level readPermission."
                    ),
                    affected_component=f"provider {comp['name']}",
                    permission=f"readPerm={read_perm}, fallback={base_perm}",
                    recommendation=(
                        f"Add android:writePermission with the same signature-level protection "
                        f"as readPermission, or set android:permission to signature-level as "
                        f"well. Do not rely on a weak fallback permission to protect file "
                        f"operations."
                    ),
                    attack_scenario=(
                        f"The attacker app declares:\n"
                        f"  <uses-permission android:name=\"{base_perm}\" />\n"
                        f"Since \"{base_perm}\" is protectionLevel={base_level or 'normal'}, "
                        f"it is granted automatically.\n\n"
                        f"Exploit code:\n"
                        f"  Uri uri = Uri.parse(\"content://<authority>/data/data/com.victim/shared_prefs/secrets.xml\");\n"
                        f"  // Request \"w\" mode — Android only checks fallback permission (weak)\n"
                        f"  ParcelFileDescriptor pfd = getContentResolver().openFile(uri, \"w\", null);\n"
                        f"  // Provider ignores mode, returns read-only fd\n"
                        f"  InputStream is = new FileInputStream(pfd.getFileDescriptor());\n"
                        f"  Log.d(\"evil\", new String(is.readAllBytes()));\n"
                        f"  // Reads file despite not holding signature-level readPermission"
                    ),
                ))

        # Case 4: writePermission is STRONG, no readPermission, fallback permission is WEAK
        # The developer intended writes to be signature-protected, but openFile("r") only
        # needs the weak fallback → attacker can read files that may reveal write-protected data.
        if (write_perm and not read_perm and base_perm
                and write_perm != base_perm):
            write_level = _get_protection_level(write_perm, manifest)
            base_level = _get_protection_level(base_perm, manifest)
            if _is_strong_protection(write_level) and _is_weak_protection(base_level):
                findings.append(Finding(
                    check="Provider Permission Gap",
                    severity=Severity.HIGH,
                    title=(
                        f"Provider '{comp['name']}' — writePermission is signature-level but "
                        f"openFile(\"r\") only requires weak fallback permission"
                    ),
                    description=(
                        f"The exported <provider> '{comp['name']}' declares:\n"
                        f"  android:writePermission=\"{write_perm}\" "
                        f"(protectionLevel={write_level or 'signature'})\n"
                        f"  android:permission=\"{base_perm}\" "
                        f"(protectionLevel={base_level or 'normal (default)'})\n"
                        f"  No android:readPermission is set.\n\n"
                        f"For file operations, Android checks permissions based on the caller's "
                        f"requested mode: openFile(uri, \"w\") checks writePermission (signature), "
                        f"but openFile(uri, \"r\") checks readPermission — which is absent, so "
                        f"it falls back to android:permission (\"{base_perm}\", which is "
                        f"protectionLevel={base_level or 'normal'}).\n\n"
                        f"An attacker holding only \"{base_perm}\" (a normal/weak permission) "
                        f"can call query() and openFile(uri, \"r\") to read all provider data "
                        f"without needing the signature-level writePermission."
                    ),
                    affected_component=f"provider {comp['name']}",
                    permission=f"writePerm={write_perm}, fallback={base_perm}",
                    recommendation=(
                        f"Add android:readPermission with the same signature-level protection "
                        f"as writePermission, or set android:permission to signature-level as "
                        f"well. Do not rely on a weak fallback permission to protect read "
                        f"operations."
                    ),
                    attack_scenario=(
                        f"The attacker app declares:\n"
                        f"  <uses-permission android:name=\"{base_perm}\" />\n"
                        f"Since \"{base_perm}\" is protectionLevel={base_level or 'normal'}, "
                        f"it is granted automatically.\n\n"
                        f"Exploit code:\n"
                        f"  // Read via query:\n"
                        f"  Cursor c = getContentResolver().query(\n"
                        f"      Uri.parse(\"content://<authority>/path\"), null, null, null, null);\n"
                        f"  // Read via openFile:\n"
                        f"  Uri uri = Uri.parse(\"content://<authority>/data/data/com.victim/files/data.db\");\n"
                        f"  ParcelFileDescriptor pfd = getContentResolver().openFile(uri, \"r\", null);\n"
                        f"  InputStream is = new FileInputStream(pfd.getFileDescriptor());\n"
                        f"  // All read operations only need the weak fallback permission"
                    ),
                ))

    return findings


# ─────────────────────────── Report Generation ───────────────────────────

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def generate_text_report(manifest_path: str, package: str, findings: list[Finding]) -> str:
    from collections import Counter

    lines = []
    lines.append("=" * 80)
    lines.append("  ANDROID MANIFEST PERMISSION SECURITY REPORT")
    lines.append("=" * 80)
    lines.append(f"  Manifest : {manifest_path}")
    lines.append(f"  Package  : {package}")
    lines.append(f"  Findings : {len(findings)}")
    lines.append("=" * 80)

    if not findings:
        lines.append("\n  ✅ No permission misconfigurations detected.\n")
        return "\n".join(lines)

    sev_counts = Counter(f.severity for f in findings)
    lines.append("\n  SUMMARY")
    lines.append("  " + "-" * 40)
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = sev_counts.get(sev, 0)
        if count:
            marker = "🔴" if sev in (Severity.CRITICAL, Severity.HIGH) else "🟡" if sev == Severity.MEDIUM else "🟢"
            lines.append(f"  {marker} {sev}: {count}")
    lines.append("")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    for i, f in enumerate(sorted_findings, 1):
        lines.append(f"  ┌─ Finding #{i} [{f.severity}] ─ {f.check}")
        lines.append(f"  │")
        lines.append(f"  │  Title: {f.title}")
        lines.append(f"  │")
        for desc_line in f.description.split("\n"):
            lines.append(f"  │  {desc_line}")
        if f.affected_component:
            lines.append(f"  │")
            lines.append(f"  │  Affected: {f.affected_component}")
        if f.permission:
            lines.append(f"  │  Permission: {f.permission}")
        if f.attack_scenario:
            lines.append(f"  │")
            lines.append(f"  │  💀 Attack Scenario:")
            for atk_line in f.attack_scenario.split("\n"):
                lines.append(f"  │     {atk_line}")
        if f.recommendation:
            lines.append(f"  │")
            lines.append(f"  │  ✏️  Recommendation: {f.recommendation}")
        lines.append(f"  └{'─' * 75}")
        lines.append("")

    lines.append("=" * 80)
    lines.append("  END OF REPORT")
    lines.append("=" * 80)
    return "\n".join(lines)


def generate_json_report(manifest_path: str, package: str, findings: list[Finding]) -> str:
    report = {
        "manifest": manifest_path,
        "package": package,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(report, indent=2)


# ─────────────────────────── Main ───────────────────────────

def run_all_checks(manifest: ManifestData, all_declared_permissions: set, device_permissions: set | None) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_missing_protection_level(manifest))
    findings.extend(check_permission_name_typos(manifest))
    findings.extend(check_component_attribute_typos(manifest))
    findings.extend(check_ecosystem_permission_issues(manifest, all_declared_permissions, device_permissions))
    findings.extend(check_provider_permission_gaps(manifest))
    return findings


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Android Manifest Permission Security Checker"
    )
    parser.add_argument(
        "manifest",
        nargs="+",
        help="Path(s) to AndroidManifest.xml file(s). Provide multiple for ecosystem analysis.",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Write report to file instead of stdout",
    )
    parser.add_argument(
        "--skip-adb",
        action="store_true",
        help="Skip querying device permissions via adb",
    )

    args = parser.parse_args()

    quiet = args.format == "json"

    # Fetch device-registered third-party permissions via adb
    device_permissions: set | None = None
    if not args.skip_adb:
        if not quiet:
            print("[*] Querying device for registered third-party permissions via adb...", file=sys.stderr)
        device_permissions = fetch_device_permissions()
        if device_permissions is not None:
            if not quiet:
                print(f"[+] Found {len(device_permissions)} third-party permission(s) on device.", file=sys.stderr)
        else:
            if not quiet:
                print("[!] adb unavailable or no device connected. Skipping device verification.", file=sys.stderr)

    # First pass: parse all manifests and collect globally declared permissions
    manifests: list[tuple[str, ManifestData]] = []
    all_declared_permissions: set = set()
    for mpath in args.manifest:
        if not os.path.isfile(mpath):
            print(f"[ERROR] File not found: {mpath}", file=sys.stderr)
            sys.exit(1)
        manifest = parse_manifest(mpath)
        manifests.append((mpath, manifest))
        all_declared_permissions.update(manifest.declared_permissions.keys())

    # Second pass: run checks with global context
    all_findings: list[Finding] = []
    all_packages = []
    for mpath, manifest in manifests:
        findings = run_all_checks(manifest, all_declared_permissions, device_permissions)
        all_packages.append(manifest.package)
        all_findings.extend(findings)

    label = ", ".join(args.manifest)
    pkg_label = ", ".join(all_packages)

    if args.format == "json":
        report = generate_json_report(label, pkg_label, all_findings)
    else:
        report = generate_text_report(label, pkg_label, all_findings)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"[+] Report written to {args.output}")
    else:
        print(report)

    sys.exit(0)


if __name__ == "__main__":
    main()





