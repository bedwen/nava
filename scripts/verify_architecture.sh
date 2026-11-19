#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "FAIL [Gate 1]: python3 is required to run verify_architecture.sh" >&2
    exit 1
fi

python3 - "$ROOT_DIR" <<'PYEOF'
import os
import re
import sys
import unicodedata

ROOT = os.path.abspath(sys.argv[1])
ERRORS = []

SKIP_DIRS = {".git", ".gradle", ".idea", "build", "out", ".cxx"}

ALLOWED_PLUGINS = {
    "com.android.application",
    "com.android.library",
    "com.android.test",
    "org.jetbrains.kotlin.jvm",
    "org.jetbrains.kotlin.android",
    "org.jetbrains.kotlin.plugin.compose",
}

FORBIDDEN_DEPENDENCY_TOKENS = (
    "retrofit",
    "okhttp",
    "sqlcipher",
    "hilt",
    "dagger",
    "koin",
    "gson",
    "moshi",
    "kotlinx-serialization",
    "ktor",
    "glide",
    "androidx.room",
    "com.google.android.play",
    "kotlinx-datetime",
)

TEST_ONLY_CONFIGS = {
    "testImplementation",
    "androidTestImplementation",
    "testApi",
    "androidTestApi",
    "testRuntimeOnly",
    "androidTestRuntimeOnly",
    "testCompileOnly",
    "androidTestCompileOnly",
    "testFixturesImplementation",
}

LOCALE_ZONE_PATTERNS = (
    re.compile(r"/src/main/res/values-(?:[a-z]{2,3}(?:-(?:r[A-Z]{2}|[A-Z][a-z]{3}|[0-9]{3}))?|b\+[A-Za-z0-9+]+)/"),
    re.compile(r"/src/main/assets/locale/"),
    re.compile(r"/src/test/resources/locale/"),
    re.compile(r"/src/androidTest/resources/locale/"),
)

ASCII_SOURCE_EXTS = {".kt", ".kts", ".java", ".cpp", ".h", ".toml", ".sh", ".properties", ".pro"}


def rel_path(path):
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def is_locale_zone(rpath):
    wrapped = "/" + rpath
    return any(p.search(wrapped) for p in LOCALE_ZONE_PATTERNS)


def walk_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            yield os.path.join(dirpath, fname)


def strip_c_comments(text):
    out = []
    i = 0
    n = len(text)
    in_str = False
    in_char = False
    in_triple = False
    while i < n:
        ch = text[i]
        if in_triple:
            out.append(ch)
            if text[i:i + 3] == '"""':
                out.append('""')
                i += 3
                in_triple = False
                continue
            i += 1
        elif in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
        elif in_char:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
        else:
            if text[i:i + 3] == '"""':
                in_triple = True
                out.append('"""')
                i += 3
            elif ch == '"':
                in_str = True
                out.append(ch)
                i += 1
            elif ch == "'":
                in_char = True
                out.append(ch)
                i += 1
            elif ch == "/" and i + 1 < n and text[i + 1] == "/":
                while i < n and text[i] != "\n":
                    i += 1
            elif ch == "/" and i + 1 < n and text[i + 1] == "*":
                i += 2
                while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 2
            else:
                out.append(ch)
                i += 1
    return "".join(out)


def find_forbidden_token(text):
    lower_text = text.lower()
    for bad in FORBIDDEN_DEPENDENCY_TOKENS:
        if re.search(r'(?<![a-z0-9])' + re.escape(bad) + r'(?![a-z0-9])', lower_text):
            return bad
    return None


def check_manifests(all_files):
    for fpath in all_files:
        if os.path.basename(fpath) == "AndroidManifest.xml":
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            stripped = re.sub(r"<!--.*?-->", "", content, flags=re.DOTALL)
            rp = rel_path(fpath)
            if "android.permission.INTERNET" in stripped:
                ERRORS.append(f"[Rule 1] Forbidden android.permission.INTERNET in {rp}")
            if "MANAGE_EXTERNAL_STORAGE" in stripped:
                ERRORS.append(f"[Rule 1] Forbidden MANAGE_EXTERNAL_STORAGE in {rp}")


def parse_toml_catalog(toml_path):
    libraries = {}
    plugins = {}
    if not os.path.exists(toml_path):
        ERRORS.append("[Rule 2] Missing gradle/libs.versions.toml")
        return libraries, plugins

    with open(toml_path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    section = None
    for lineno, line in enumerate(raw.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        bad_tok = find_forbidden_token(stripped)
        if bad_tok:
            ERRORS.append(f"[Rule 2] Forbidden dependency token '{bad_tok}' in gradle/libs.versions.toml:{lineno}")
        if "=" not in stripped:
            continue
        key, val = [p.strip() for p in stripped.split("=", 1)]
        norm_key = key.replace("-", ".").replace("_", ".")
        if section == "libraries":
            m_group = re.search(r'group\s*=\s*"([^"]+)"', val)
            m_name = re.search(r'name\s*=\s*"([^"]+)"', val)
            m_mod = re.search(r'module\s*=\s*"([^":]+):([^"]+)"', val)
            if m_group and m_name:
                libraries[norm_key] = (m_group.group(1), m_name.group(1))
            elif m_mod:
                libraries[norm_key] = (m_mod.group(1), m_mod.group(2))
            elif val.startswith('"') and ":" in val:
                coords = val.strip('"').split(":")
                if len(coords) >= 2:
                    libraries[norm_key] = (coords[0], coords[1])
        elif section == "plugins":
            m_id = re.search(r'id\s*=\s*"([^"]+)"', val)
            if m_id:
                plugins[norm_key] = m_id.group(1)
            elif val.startswith('"') and ":" in val:
                plugins[norm_key] = val.strip('"').split(":")[0]
    return libraries, plugins


def classify_dependency(group, artifact):
    if group == "com.android.tools.build":
        return "BUILD_ONLY"
    if group == "org.jetbrains.kotlin" and artifact.startswith("kotlin-stdlib"):
        return "RUNTIME"
    if group == "org.jetbrains.kotlinx":
        if artifact.startswith("kotlinx-coroutines-core"):
            return "RUNTIME"
        if artifact.startswith("kotlinx-coroutines-android"):
            return "ANDROID_RUNTIME"
        if artifact.startswith("kotlinx-coroutines-test"):
            return "TEST_ONLY"
        return None
    if group == "com.google.ai.edge.litertlm" or group == "com.google.ai.edge.litert":
        return "CORE_AI_ONLY"
    if group == "junit" and artifact == "junit":
        return "TEST_ONLY"
    if group == "org.junit" or group.startswith("org.junit."):
        return "TEST_ONLY"
    if group.startswith("androidx."):
        if (
            group == "androidx.test"
            or group.startswith("androidx.test.")
            or (group == "androidx.compose.ui" and artifact.startswith("ui-test"))
            or group == "androidx.benchmark"
            or group.startswith("androidx.benchmark.")
        ):
            return "TEST_ONLY"
        return "ANDROIDX_RUNTIME"
    return None


def is_allowed_plugin(plugin_id):
    return plugin_id in ALLOWED_PLUGINS or plugin_id.startswith("com.android.tools.build:")


def extract_balanced_parens(text, open_idx):
    n = len(text)
    i = open_idx + 1
    depth = 1
    in_str = False
    in_char = False
    in_triple = False
    while i < n:
        ch = text[i]
        if in_triple:
            if text[i:i + 3] == '"""':
                i += 3
                in_triple = False
                continue
            i += 1
        elif in_str:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
        elif in_char:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "'":
                in_char = False
            i += 1
        else:
            if text[i:i + 3] == '"""':
                in_triple = True
                i += 3
            elif ch == '"':
                in_str = True
                i += 1
            elif ch == "'":
                in_char = True
                i += 1
            elif ch == "(":
                depth += 1
                i += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1:i], i + 1
                i += 1
            else:
                i += 1
    return None, n


def unwrap_outer_call(expr, wrapper_names):
    stripped = expr.strip()
    for name in wrapper_names:
        m = re.match(r'^' + name + r'\s*\(', stripped)
        if m:
            inner, end_idx = extract_balanced_parens(stripped, m.end() - 1)
            if inner is not None and stripped[end_idx:].strip() == "":
                return inner.strip(), True
    return stripped, False


def inside_any_span(pos, spans):
    for start, end in spans:
        if start <= pos < end:
            return True
    return False


def validate_plugin_id(pid, rp, lineno, is_domain_build):
    if not is_allowed_plugin(pid):
        ERRORS.append(f"[Rule 2] Disallowed plugin '{pid}' in {rp}:{lineno}")
    if is_domain_build and pid != "org.jetbrains.kotlin.jvm":
        ERRORS.append(f"[Rule 3] Non-JVM plugin '{pid}' forbidden in :domain ({rp}:{lineno})")


def check_dependencies(all_files):
    toml_path = os.path.join(ROOT, "gradle", "libs.versions.toml")
    libraries, plugins = parse_toml_catalog(toml_path)

    for norm_key, (group, artifact) in sorted(libraries.items()):
        if classify_dependency(group, artifact) is None:
            ERRORS.append(f"[Rule 2] Disallowed library '{group}:{artifact}' in libs.versions.toml ({norm_key})")

    for norm_key, pid in sorted(plugins.items()):
        if not is_allowed_plugin(pid):
            ERRORS.append(f"[Rule 2] Disallowed plugin '{pid}' in libs.versions.toml ({norm_key})")

    dep_call_re = re.compile(
        r'(?<![A-Za-z0-9_.])('
        r'implementation|api|compileOnly|runtimeOnly|debugImplementation|releaseImplementation|'
        r'testImplementation|androidTestImplementation|testApi|androidTestApi|testRuntimeOnly|'
        r'androidTestRuntimeOnly|testCompileOnly|androidTestCompileOnly|testFixturesImplementation|'
        r'classpath|kapt|ksp|annotationProcessor'
        r')\s*\('
    )
    plugin_id_re = re.compile(r'(?<![A-Za-z0-9_.])\bid\s*\(')
    plugin_alias_re = re.compile(r'(?<![A-Za-z0-9_.])\balias\s*\(')
    plugin_kotlin_re = re.compile(r'(?<![A-Za-z0-9_.])\bkotlin\s*\(')
    plugin_apply_re = re.compile(r'(?<![A-Za-z0-9_.])\bapply\s*\(')

    for fpath in all_files:
        if not fpath.endswith(".gradle.kts"):
            continue
        rp = rel_path(fpath)
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            cleaned = strip_c_comments(fh.read())

        bad_tok = find_forbidden_token(cleaned)
        if bad_tok:
            ERRORS.append(f"[Rule 2] Forbidden dependency token '{bad_tok}' in {rp}")

        is_domain_build = rp == "domain/build.gradle.kts"
        is_core_ai_or_spike = rp == "core-ai/build.gradle.kts" or rp.startswith("spikes/")

        dep_spans = []
        for dm in dep_call_re.finditer(cleaned):
            config = dm.group(1)
            open_idx = dm.end() - 1
            lineno = cleaned.count("\n", 0, dm.start()) + 1
            inner, end_idx = extract_balanced_parens(cleaned, open_idx)
            if inner is None:
                ERRORS.append(f"[Rule 2] Unclosed dependency call '{config}(...)' in {rp}:{lineno}")
                continue
            dep_spans.append((dm.start(), end_idx))
            arg = inner.strip()

            if config in ("kapt", "ksp", "annotationProcessor"):
                ERRORS.append(f"[Rule 2] Annotation processor configuration '{config}' forbidden in {rp}:{lineno}")
                continue

            changed = True
            while changed:
                arg, changed = unwrap_outer_call(arg, ("platform", "enforcedPlatform", "testFixtures"))

            if re.match(r'^project\s*\(', arg):
                if is_domain_build:
                    ERRORS.append(f"[Rule 3] Module dependency '{arg}' forbidden in :domain ({rp}:{lineno})")
                continue

            if re.match(r'^(?:files|fileTree)\s*\(', arg):
                ERRORS.append(f"[Rule 2] Unverified local jar dependency '{arg}' forbidden in {rp}:{lineno}")
                continue

            group = None
            artifact = None
            m_kotlin_dep = re.match(
                r'^kotlin\s*\(\s*"([^"]+)"(?:\s*,\s*(?:version\s*=\s*)?"[^"]*")?\s*\)$',
                arg,
            )
            m_str_dep = re.match(r'^"([^"]+)"$', arg)
            m_group = re.search(r'\bgroup\s*=\s*"([^"]+)"', arg)
            m_name = re.search(r'\bname\s*=\s*"([^"]+)"', arg)
            m_module = re.search(r'\bmodule\s*=\s*"([^":]+):([^"]+)"', arg)

            if re.match(r'^libs\.[A-Za-z0-9_.]+$', arg):
                alias = arg[len("libs."):].strip()
                coords = libraries.get(alias)
                if coords is None:
                    ERRORS.append(f"[Rule 2] Unknown version-catalog alias '{arg}' in {rp}:{lineno}")
                    continue
                group, artifact = coords
            elif m_kotlin_dep:
                group = "org.jetbrains.kotlin"
                artifact = "kotlin-" + m_kotlin_dep.group(1)
            elif m_str_dep:
                coord = m_str_dep.group(1).split("@", 1)[0]
                parts = coord.split(":")
                if len(parts) < 2:
                    ERRORS.append(f"[Rule 2] Malformed dependency coordinate '{arg}' in {rp}:{lineno}")
                    continue
                group, artifact = parts[0], parts[1]
            elif m_group and m_name:
                group, artifact = m_group.group(1), m_name.group(1)
            elif m_module:
                group = m_module.group(1)
                artifact = m_module.group(2).split("@", 1)[0]
            else:
                ERRORS.append(f"[Rule 2] Unrecognized dependency expression '{arg}' in {rp}:{lineno}")
                continue

            cat = classify_dependency(group, artifact)
            if cat is None:
                ERRORS.append(f"[Rule 2] Disallowed dependency '{group}:{artifact}' in {rp}:{lineno}")
                continue
            if cat == "BUILD_ONLY" and config != "classpath":
                ERRORS.append(
                    f"[Rule 2] Build-scope dependency '{group}:{artifact}' used in '{config}' in {rp}:{lineno}"
                )
            if config == "classpath" and cat != "BUILD_ONLY":
                ERRORS.append(
                    f"[Rule 2] Non-buildscript dependency '{group}:{artifact}' used in 'classpath' in {rp}:{lineno}"
                )
            if cat == "TEST_ONLY" and config not in TEST_ONLY_CONFIGS:
                ERRORS.append(
                    f"[Rule 2] Test-only dependency '{group}:{artifact}' used in '{config}' in {rp}:{lineno}"
                )
            if cat == "CORE_AI_ONLY" and not is_core_ai_or_spike:
                ERRORS.append(
                    f"[Rule 2] LiteRT dependency '{group}:{artifact}' allowed only in :core-ai or spikes/ ({rp}:{lineno})"
                )
            if is_domain_build and cat in ("ANDROID_RUNTIME", "ANDROIDX_RUNTIME", "CORE_AI_ONLY", "BUILD_ONLY"):
                ERRORS.append(
                    f"[Rule 3] Android/LiteRT/build dependency '{group}:{artifact}' forbidden in :domain ({rp}:{lineno})"
                )

        for m in plugin_id_re.finditer(cleaned):
            if inside_any_span(m.start(), dep_spans):
                continue
            lineno = cleaned.count("\n", 0, m.start()) + 1
            inner, _ = extract_balanced_parens(cleaned, m.end() - 1)
            if inner is None:
                ERRORS.append(f"[Rule 2] Unclosed plugin id(...) call in {rp}:{lineno}")
                continue
            pm = re.match(r'^"([^"]+)"$', inner.strip())
            if pm:
                validate_plugin_id(pm.group(1), rp, lineno, is_domain_build)

        for m in plugin_alias_re.finditer(cleaned):
            if inside_any_span(m.start(), dep_spans):
                continue
            lineno = cleaned.count("\n", 0, m.start()) + 1
            inner, _ = extract_balanced_parens(cleaned, m.end() - 1)
            if inner is None:
                ERRORS.append(f"[Rule 2] Unclosed plugin alias(...) call in {rp}:{lineno}")
                continue
            am = re.match(r'^libs\.plugins\.([A-Za-z0-9_.]+)$', inner.strip())
            if am:
                alias = am.group(1)
                pid = plugins.get(alias)
                if pid is None:
                    ERRORS.append(f"[Rule 2] Unknown plugin alias 'libs.plugins.{alias}' in {rp}:{lineno}")
                else:
                    validate_plugin_id(pid, rp, lineno, is_domain_build)

        for m in plugin_kotlin_re.finditer(cleaned):
            if inside_any_span(m.start(), dep_spans):
                continue
            lineno = cleaned.count("\n", 0, m.start()) + 1
            inner, _ = extract_balanced_parens(cleaned, m.end() - 1)
            if inner is None:
                ERRORS.append(f"[Rule 2] Unclosed kotlin(...) plugin call in {rp}:{lineno}")
                continue
            km = re.match(r'^"([^"]+)"$', inner.strip())
            if km:
                validate_plugin_id("org.jetbrains.kotlin." + km.group(1), rp, lineno, is_domain_build)

        for m in plugin_apply_re.finditer(cleaned):
            if inside_any_span(m.start(), dep_spans):
                continue
            lineno = cleaned.count("\n", 0, m.start()) + 1
            inner, _ = extract_balanced_parens(cleaned, m.end() - 1)
            if inner is None:
                ERRORS.append(f"[Rule 2] Unclosed apply(...) call in {rp}:{lineno}")
                continue
            ap = re.search(r'\bplugin\s*=\s*"([^"]+)"', inner)
            if ap:
                validate_plugin_id(ap.group(1), rp, lineno, is_domain_build)


def check_domain_isolation(all_files):
    import_re = re.compile(r'^\s*import\s+(android|androidx)(?:\.|\s|$)')
    fqn_re = re.compile(r'\b(android|androidx)\.[a-zA-Z0-9_]+\.[A-Z]')
    for fpath in all_files:
        rp = rel_path(fpath)
        if not (rp.startswith("domain/src/") and (rp.endswith(".kt") or rp.endswith(".java"))):
            continue
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            cleaned = strip_c_comments(fh.read())
        for lineno, line in enumerate(cleaned.splitlines(), start=1):
            if import_re.search(line):
                ERRORS.append(f"[Rule 3] Forbidden Android import in :domain at {rp}:{lineno}: {line.strip()}")
            elif fqn_re.search(line):
                ERRORS.append(f"[Rule 3] Forbidden Android qualified reference in :domain at {rp}:{lineno}: {line.strip()}")


def check_neural_canvas_allocations(all_files):
    draw_entry_re = re.compile(r'\b(?:onDraw|DrawScope\b|Canvas\s*\()')
    alloc_re = re.compile(
        r'(?:\bPaint\s*\(|\bPath\s*\(|\bRectF\s*\(|\bBrush\.|\bColor\s*\(|\bmutableListOf\s*\(|\blistOf\s*\(|\bArrayList\s*\()'
    )
    for fpath in all_files:
        rp = rel_path(fpath)
        if not rp.endswith(".kt") or "/src/main/" not in ("/" + rp):
            continue
        with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
        if "NeuralCanvas" not in os.path.basename(rp) and "NeuralCanvas" not in raw:
            continue
        cleaned = strip_c_comments(raw)
        lines = cleaned.splitlines()
        in_draw = False
        brace_depth = 0
        pending_open = False
        for lineno, line in enumerate(lines, start=1):
            if not in_draw:
                if draw_entry_re.search(line):
                    pending_open = True
            if pending_open or in_draw:
                opens = line.count("{")
                closes = line.count("}")
                if pending_open and opens > 0:
                    in_draw = True
                    pending_open = False
                if in_draw:
                    m = alloc_re.search(line)
                    if m:
                        ERRORS.append(
                            f"[Rule 4] Potential heap allocation '{m.group(0)}' inside Neural Canvas draw loop at {rp}:{lineno}"
                        )
                    brace_depth += opens - closes
                    if brace_depth <= 0:
                        in_draw = False
                        brace_depth = 0


def check_english_and_ascii(all_files):
    for fpath in all_files:
        rp = rel_path(fpath)
        if is_locale_zone(rp):
            continue
        fname = os.path.basename(rp)
        _, ext = os.path.splitext(fname)
        is_values_xml = bool(re.search(r"/src/main/res/values(?:-[^/]+)?/", "/" + rp)) and fname.endswith(".xml")
        is_manifest = fname == "AndroidManifest.xml"
        if ext in ASCII_SOURCE_EXTS or is_manifest or is_values_xml:
            with open(fpath, "rb") as fh:
                data = fh.read()
            line = 1
            col = 0
            for b in data:
                if b == 10:
                    line += 1
                    col = 0
                    continue
                col += 1
                if b not in (9, 13) and not (32 <= b <= 126):
                    ERRORS.append(
                        f"[Rule 5] Non-ASCII byte 0x{b:02X} in {rp}:{line}:{col} (use \\uXXXX escapes)"
                    )
                    break
        elif ext == ".md":
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            for lineno, line_text in enumerate(content.splitlines(), start=1):
                for col, ch in enumerate(line_text, start=1):
                    if ord(ch) > 127 and unicodedata.category(ch).startswith("L"):
                        ERRORS.append(
                            f"[Rule 5] Non-ASCII letter U+{ord(ch):04X} in Markdown {rp}:{lineno}:{col}"
                        )
                        break


def main():
    all_files = list(walk_files())
    check_manifests(all_files)
    check_dependencies(all_files)
    check_domain_isolation(all_files)
    check_neural_canvas_allocations(all_files)
    check_english_and_ascii(all_files)

    if ERRORS:
        print(f"FAIL [Gate 1]: {len(ERRORS)} architecture violation(s) detected:", file=sys.stderr)
        for err in ERRORS:
            print("  - " + err, file=sys.stderr)
        sys.exit(1)
    print(f"PASS [Gate 1]: Audited {len(all_files)} files with 0 violations.")


if __name__ == "__main__":
    main()
PYEOF
