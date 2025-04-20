#!/bin/bash

set -euo pipefail

# Configuration
CORE_MOD_URL="https://raw.githubusercontent.com/eclipse-xfsc/crypto-provider-core/main/go.mod"

# Temporary file for core go.mod
TMP_CORE_MOD=$(mktemp)

# Fetch core go.mod
echo "Downloading core go.mod from GitHub..."
curl -sSL "$CORE_MOD_URL" -o "$TMP_CORE_MOD"

# Extract dependencies from core go.mod
declare -A core_deps
while read -r line; do
  # Skip empty lines and comments
  [[ -z "$line" || "$line" =~ ^// ]] && continue
  # Extract module and version
  module=$(echo "$line" | awk '{print $1}')
  version=$(echo "$line" | awk '{print $2}')
  [[ -n "$module" && -n "$version" ]] && core_deps["$module"]="$version"
done < <(awk '/require \(/,/\)/' "$TMP_CORE_MOD")

# Extract dependencies from plugin's go.mod
declare -A plugin_deps
while read -r line; do
  [[ -z "$line" || "$line" =~ ^// ]] && continue
  module=$(echo "$line" | awk '{print $1}')
  version=$(echo "$line" | awk '{print $2}')
  [[ -n "$module" && -n "$version" ]] && plugin_deps["$module"]="$version"
done < <(awk '/require \(/,/\)/' go.mod)

# Compare and update dependencies
for module in "${!core_deps[@]}"; do
  core_version="${core_deps[$module]}"
  plugin_version="${plugin_deps[$module]:-}"

  if [[ -z "$plugin_version" ]]; then
    echo "Adding missing module: $module@$core_version"
    go get "$module@$core_version"
  elif [[ "$core_version" != "$plugin_version" ]]; then
    echo "Updating module: $module from $plugin_version to $core_version"
    go get "$module@$core_version"
  fi
done

# Clean up
rm "$TMP_CORE_MOD"

# Tidy and vendor
echo "Running go mod tidy..."
go mod tidy

echo "Vendoring dependencies..."
go mod vendor

echo "Dependency synchronization complete."