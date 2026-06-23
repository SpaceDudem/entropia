#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""build.py - package and install the EntropyKit VS Code extension.

No Node.js / vsce required. The `install` action drops the extension
files straight into your user-level VS Code extensions directory; the
`vsix` action hand-rolls a `.vsix` (which is just a ZIP with a manifest)
so you can ship the extension to other machines.

Usage:
    python build.py install            # copy to ~/.vscode/extensions/
    python build.py install --insiders # ~/.vscode-insiders/extensions/
    python build.py uninstall          # remove the installed copy
    python build.py vsix               # write entropykit-<ver>.vsix here
    python build.py status             # show install path + state

After `install`, reload VS Code (Command Palette  to 
"Developer: Reload Window") to pick up the grammar.
"""

import argparse
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Files that ship with the extension. Anything else in the directory
# (this script, build artifacts, the README header image, ...) stays out.
SHIPPED = [
    "package.json",
    "language-configuration.json",
    "README.md",
    "syntaxes/entropykit.tmLanguage.json",
    "icons/etpy.svg",
]

# Extra binaries that get copied in alongside `SHIPPED` when present.
# The debugger registration in package.json points at
# `./bin/entc-debug.exe`; we look for it in the workspace's
# `target/release/` first, then `target/debug/`. Builds with neither
# fall back to syntax-only (debugger commands then fail with a clear
# "binary not found" - better than silently shipping a stale one).
DEBUG_BIN = "entc-debug.exe"
DEBUG_BIN_DEST = "bin/entc-debug.exe"


def read_manifest() -> dict:
    """Pull the extension's identity out of package.json so the rest of
    the script doesn't hard-code names that could drift."""
    with (HERE / "package.json").open(encoding="utf-8") as f:
        return json.load(f)


def install_dir_name(manifest: dict) -> str:
    publisher = manifest.get("publisher", "entropykit")
    name      = manifest["name"]
    version   = manifest["version"]
    # VS Code expects `<publisher>.<name>-<version>` (no underscores).
    return f"{publisher}.{name}-{version}"


def vscode_ext_root(insiders: bool) -> Path:
    """Locate the user's VS Code extensions directory.

    Order of precedence:
      1. `$VSCODE_EXTENSIONS` (explicit override).
      2. `--insiders`  to  `.vscode-insiders/extensions/`.
      3. Default `.vscode/extensions/` in the user's home.
    """
    override = os.environ.get("VSCODE_EXTENSIONS")
    if override:
        return Path(override).expanduser()
    base = ".vscode-insiders" if insiders else ".vscode"
    if sys.platform == "win32":
        home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    else:
        home = Path.home()
    return home / base / "extensions"


def iter_shipped_files() -> list[Path]:
    paths = []
    for rel in SHIPPED:
        p = HERE / rel
        if not p.exists():
            print(f"[warn] missing: {rel}", file=sys.stderr)
            continue
        paths.append(p)
    return paths


def find_debug_bin() -> Path | None:
    """Locate the freshly-built entc-debug.exe. We don't shell out to
    cargo - the caller is expected to have run `cargo build -p
    entc-debug` (or `--release`) themselves. Return None if neither
    profile has it, so syntax-only installs still work."""
    workspace_root = HERE.parent.parent
    for profile in ("release", "debug"):
        candidate = workspace_root / "target" / profile / DEBUG_BIN
        if candidate.exists():
            return candidate
    return None


# ---------------------------------------------------------------- actions

def do_install(insiders: bool) -> int:
    manifest = read_manifest()
    target   = vscode_ext_root(insiders) / install_dir_name(manifest)
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    for src in iter_shipped_files():
        rel = src.relative_to(HERE)
        dst = target / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    # Optional debugger backend.
    bin_src = find_debug_bin()
    if bin_src is not None:
        dst = target / DEBUG_BIN_DEST
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bin_src, dst)
        print(f"  + bundled {bin_src.name} from {bin_src.relative_to(HERE.parent.parent)}")
    else:
        print(f"[warn] no {DEBUG_BIN} found under target/{{release,debug}}/ - "
              "F5 debugger will report 'program not found' until you run "
              "`cargo build -p entc-debug` then re-install.")
    print(f"installed {manifest['name']} v{manifest['version']} -> {target}")
    print("reload VS Code (Command Palette -> 'Developer: Reload Window').")
    return 0


def do_uninstall(insiders: bool) -> int:
    manifest = read_manifest()
    target   = vscode_ext_root(insiders) / install_dir_name(manifest)
    if not target.exists():
        print(f"nothing installed at {target}")
        return 0
    shutil.rmtree(target)
    print(f"removed {target}")
    return 0


def do_status(insiders: bool) -> int:
    manifest = read_manifest()
    target   = vscode_ext_root(insiders) / install_dir_name(manifest)
    print(f"extension id      : {install_dir_name(manifest)}")
    print(f"source            : {HERE}")
    print(f"would install to  : {target}")
    print(f"currently installed: {'yes' if target.exists() else 'no'}")
    return 0


def do_vsix() -> int:
    """Build a .vsix package by hand. A VSIX is a zip with:
       /[Content_Types].xml
       /extension.vsixmanifest
       /extension/<files...>
    The official `vsce` does more (asset bundling, dependency walking) -
    we cover the syntax-highlight-only case which is what we need."""
    manifest = read_manifest()
    out      = HERE / f"{manifest['name']}-{manifest['version']}.vsix"

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        # 1. The Open Packaging Conventions content-types declaration.
        z.writestr("[Content_Types].xml", _CONTENT_TYPES_XML)
        # 2. The VSIX manifest VS Code reads at install time.
        z.writestr("extension.vsixmanifest", _build_vsixmanifest(manifest))
        # 3. The actual extension files, namespaced under `extension/`.
        for src in iter_shipped_files():
            arcname = "extension/" + str(src.relative_to(HERE)).replace("\\", "/")
            z.write(src, arcname)
        # 4. Optional debug backend.
        bin_src = find_debug_bin()
        if bin_src is not None:
            z.write(bin_src, "extension/" + DEBUG_BIN_DEST)
            print(f"  + bundled {bin_src.name}")
        else:
            print(f"[warn] no {DEBUG_BIN} found - VSIX will install without debugger backend.")

    size_kb = out.stat().st_size / 1024
    print(f"wrote {out.name} ({size_kb:.1f} KB)")
    print(f"install on any machine with:  code --install-extension {out}")
    return 0


# ---------------------------------------------------------------- assets

_CONTENT_TYPES_XML = """<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json" />
  <Default Extension="md" ContentType="text/markdown" />
  <Default Extension="vsixmanifest" ContentType="text/xml" />
</Types>
"""


def _build_vsixmanifest(manifest: dict) -> str:
    publisher = manifest.get("publisher", "entropykit")
    name      = manifest["name"]
    version   = manifest["version"]
    display   = manifest.get("displayName", name)
    desc      = manifest.get("description", "")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="{name}" Version="{version}" Publisher="{publisher}" />
    <DisplayName>{display}</DisplayName>
    <Description xml:space="preserve">{desc}</Description>
    <Categories>Programming Languages</Categories>
    <Tags>EntropyKit,shellcode,red team,syntax</Tags>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" Version="[1.50.0,)" />
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true" />
  </Assets>
</PackageManifest>
"""


# ---------------------------------------------------------------- entry

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="build.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("action", choices=["install", "uninstall", "vsix", "status"])
    p.add_argument(
        "--insiders",
        action="store_true",
        help="target .vscode-insiders instead of .vscode",
    )
    args = p.parse_args(argv)

    if args.action == "install":   return do_install(args.insiders)
    if args.action == "uninstall": return do_uninstall(args.insiders)
    if args.action == "status":    return do_status(args.insiders)
    if args.action == "vsix":      return do_vsix()
    return 1


if __name__ == "__main__":
    sys.exit(main())
