#!/bin/bash

set -euo pipefail

# Configuration
CORE_MOD_URL="https://raw.githubusercontent.com/eclipse-xfsc/crypto-provider-core/main/go.mod"

# Temporary files
TMP_CORE_MOD=$(mktemp)
TMP_CORE_DEPS=$(mktemp)
TMP_PLUGIN_DEPS=$(mktemp)

# Fetch core go.mod
echo "Downloading core go.mod from GitHub..."
curl -sSL "$CORE_MOD_URL" -o "$TMP_CORE_MOD"

# Extract dependencies from core go.mod
awk '/require \(/,/\)/' "$TMP_CORE_MOD" | \
  grep -vE '^\s*(require|\))' | \
  awk '{print $1, $2}' | sort > "$TMP_CORE_DEPS"

# Extract dependencies from plugin's go.mod
awk '/require \(/,/\)/' go.mod | \
  grep -vE '^\s*(require|\))' | \
  awk '{print $1, $2}' | sort > "$TMP_PLUGIN_DEPS"

# Compare and update dependencies
while read -r module version; do
  plugin_line=$(grep "^$module " "$TMP_PLUGIN_DEPS" || true)
  if [ -z "$plugin_line" ]; then
    echo "Adding missing module: $module@$version"
    go get "$module@$version"
  else
    plugin_version=$(echo "$plugin_line" | awk '{print $2}')
    if [ "$version" != "$plugin_version" ]; then
      echo "Updating module: $module from $plugin_version to $version"
      go get "$module@$version"
    fi
  fi
done < "$TMP_CORE_DEPS"

# Clean up temporary files
rm "$TMP_CORE_MOD" "$TMP_CORE_DEPS" "$TMP_PLUGIN_DEPS"

# Tidy and vendor
echo "Running go mod tidy..."
go mod tidy

echo "Dependency synchronization complete."
