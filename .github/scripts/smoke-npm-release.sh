#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

mode="${1:-}"
case "$mode" in
  all)
    package_dirs=(hdp-mcp hdp-cli hdp-autogen-ts)
    package_names=('@helixar_ai/hdp' '@helixar_ai/hdp-mcp' '@helixar_ai/hdp-autogen')
    ;;
  autogen)
    package_dirs=(hdp-autogen-ts)
    package_names=('@helixar_ai/hdp' '@helixar_ai/hdp-autogen')
    ;;
  *)
    echo "Usage: $0 all|autogen" >&2
    exit 2
    ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
tmp_dir="$(mktemp -d)"
pack_dir="$tmp_dir/packed"
install_dir="$tmp_dir/installed"
mkdir -p "$pack_dir" "$install_dir" "$tmp_dir/manifests"

restore_manifests() {
  for package_dir in "${package_dirs[@]}"; do
    cp "$tmp_dir/manifests/$package_dir.json" "$repo_root/packages/$package_dir/package.json"
  done
  rm -rf "$tmp_dir"
}
trap restore_manifests EXIT

hdp_version="$(node -p "require('$repo_root/package.json').version")"
for package_dir in "${package_dirs[@]}"; do
  cp "$repo_root/packages/$package_dir/package.json" "$tmp_dir/manifests/$package_dir.json"
done

(
  cd "$repo_root"
  npm pack --silent --pack-destination "$pack_dir" .
)

for package_dir in "${package_dirs[@]}"; do
  package_path="$repo_root/packages/$package_dir"
  (
    cd "$package_path"
    npm pkg set "dependencies.@helixar_ai/hdp=^${hdp_version}"
    node -e '
      const manifest = require("./package.json");
      const sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
      const fileDependencies = sections.flatMap((section) =>
        Object.entries(manifest[section] || {})
          .filter(([, spec]) => typeof spec === "string" && spec.startsWith("file:"))
          .map(([name, spec]) => `${section}.${name}=${spec}`)
      );
      if (fileDependencies.length > 0) {
        console.error(`Cannot pack ${manifest.name} with file dependencies: ${fileDependencies.join(", ")}`);
        process.exit(1);
      }
    '
    npm pack --silent --pack-destination "$pack_dir"
  )
done

for package_dir in "${package_dirs[@]}"; do
  cp "$tmp_dir/manifests/$package_dir.json" "$repo_root/packages/$package_dir/package.json"
done

echo "Installing packed npm packages in an empty directory"
(
  cd "$install_dir"
  npm install --no-audit --no-fund "$pack_dir"/*.tgz
  npm ls json-canonicalize
  node -e 'require("@helixar_ai/hdp"); console.log("CommonJS require: @helixar_ai/hdp: PASS")'
  if [[ "$mode" == "all" ]]; then
    node -e 'require("@helixar_ai/hdp-mcp"); console.log("CommonJS require: @helixar_ai/hdp-mcp: PASS")'
    node -e 'require("@helixar_ai/hdp-autogen"); console.log("CommonJS require: @helixar_ai/hdp-autogen: PASS")'

    node -e '
      const fs = require("node:fs");
      const vector = require(process.argv[1]);
      fs.writeFileSync(process.argv[2], JSON.stringify(vector.token));
    ' "$repo_root/tests/vectors/section3-validation.json" "$tmp_dir/token.json"
    cli_entry="$install_dir/node_modules/hdp-validate/dist/cli.js"
    "$install_dir/node_modules/.bin/hdp-validate" "$tmp_dir/token.json" >/dev/null
    echo "CLI executable: hdp-validate: PASS"
    node -e '
      const [entry, token] = process.argv.slice(1);
      process.argv = [process.execPath, entry, token];
      require(entry);
    ' "$cli_entry" "$tmp_dir/token.json" >/dev/null
    echo "CommonJS require: hdp-validate CLI entry: PASS"
    node --input-type=module -e '
      import { pathToFileURL } from "node:url";
      const [entry, token] = process.argv.slice(1);
      process.argv = [process.execPath, entry, token];
      await import(pathToFileURL(entry));
    ' "$cli_entry" "$tmp_dir/token.json" >/dev/null
    echo "ESM import: hdp-validate CLI entry: PASS"
  else
    node -e 'require("@helixar_ai/hdp-autogen"); console.log("CommonJS require: @helixar_ai/hdp-autogen: PASS")'
  fi
)

cat > "$install_dir/check-esm-imports.mjs" <<'EOF'
const packages = process.argv.slice(2)
let failures = 0

for (const packageName of packages) {
  try {
    await import(packageName)
    console.log(`ESM import: ${packageName}: PASS`)
  } catch (error) {
    console.error(`ESM import: ${packageName}: FAIL`, error)
    failures += 1
  }
}

if (failures > 0) process.exit(1)
EOF

(
  cd "$install_dir"
  node "$install_dir/check-esm-imports.mjs" "${package_names[@]}"
)
