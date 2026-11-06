#!/usr/bin/env bash
set -euo pipefail

# Generate a REAL tap formula only after vetted, paired compiler+CLI archives
# have been published in a public GitHub release. Do not use candidate checksums.
if [[ $# -ne 4 ]]; then
  echo "usage: $0 vX.Y.Z ARM64_SHA256 INTEL_SHA256 OUTPUT_FORMULA" >&2
  exit 2
fi
tag="$1"
arm_sha="$2"
intel_sha="$3"
destination="$4"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "expected a stable semver release tag like v0.1.0" >&2
  exit 2
fi
for digest in "$arm_sha" "$intel_sha"; do
  if [[ ! "$digest" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "expected 64-character SHA-256 checksums" >&2
    exit 2
  fi
done
version="${tag#v}"
# Reject output aliases before any filesystem mutation. Atomic renames do not
# dereference symlinks or corrupt other hardlinks, but refusing aliases also
# prevents surprising removal of caller-owned paths.
preflight_destination() {
  if [[ -z "$destination" || "$destination" == */ || -L "$destination" ]]; then
    echo "invalid or symlinked formula destination" >&2
    return 2
  fi
  if [[ -e "$destination" ]]; then
    if [[ ! -f "$destination" ]]; then
      echo "formula destination must be a regular file" >&2
      return 2
    fi
    local links
    if links="$(stat -c %h "$destination" 2>/dev/null)"; then
      :
    elif links="$(stat -f %l "$destination" 2>/dev/null)"; then
      :
    else
      echo "cannot attest formula destination link count" >&2
      return 2
    fi
    if [[ ! "$links" =~ ^[0-9]+$ ]] || (( links > 1 )); then
      echo "hardlinked or unverified formula destination" >&2
      return 2
    fi
  fi
}
preflight_destination
parent="${destination%/*}"
if [[ "$parent" == "$destination" ]]; then parent="."; fi
mkdir -p -- "$parent"
# Write into a fresh same-directory file, then atomically replace the target
# only after complete generation. Failure must leave the previous formula
# byte-identical and remove transient files.
tmp="$(mktemp "$parent/.oreslang-formula.XXXXXXXX")"
trap 'rm -f -- "$tmp"' EXIT

cat > "$tmp" <<RUBY
# Generated after an approved binary release. Never substitute private CI
# artifact URLs or unverified compiler checksums.
class Oreslang < Formula
  desc "AttoLang compiler and developer CLI"
  homepage "https://github.com/ores-truffle-oreslang/oreslang-cli"
  version "${version}"
  depends_on :macos

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/ores-truffle-oreslang/oreslang-cli/releases/download/${tag}/oreslang-compiler-macos-arm64.tar.gz"
      sha256 "${arm_sha}"
    else
      url "https://github.com/ores-truffle-oreslang/oreslang-cli/releases/download/${tag}/oreslang-compiler-macos-x86_64.tar.gz"
      sha256 "${intel_sha}"
    end
  end

  def install
    bin.install "atto", "oreslang", "oreslang-compiler"
    prefix.install "provenance.json"
  end

  test do
    assert_match "atto", shell_output("#{bin}/atto version")
    assert_match "oreslang", shell_output("#{bin}/oreslang version")
    assert_predicate bin/"oreslang-compiler", :executable?
    (testpath/"hello.atto").write "pub routine main(): void { return; }\n"
    system bin/"atto", "check", testpath/"hello.atto"
    system bin/"oreslang", "check", testpath/"hello.atto"
    (testpath/"hello.ores").write "pub routine main(): void { return; }\n"
    system bin/"oreslang", "check", testpath/"hello.ores"
  end
end
RUBY
chmod 0644 "$tmp"
preflight_destination
mv -f -- "$tmp" "$destination"
trap - EXIT
echo "Wrote $destination; validate with brew style/audit/install/test before publishing." >&2
