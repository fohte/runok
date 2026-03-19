#!/usr/bin/env bash
# Generate a versioned release-notes page from next.md when a new tag is created.
#
# Required environment variables:
#   TAG_NAME          - Git tag for this release (e.g. v0.3.0)
#   GITHUB_REPOSITORY - owner/repo (e.g. fohte/runok)
#
# Optional:
#   RELEASES_DIR - Path to the releases directory
#                  (default: docs/src/content/docs/releases)
#   RELEASE_DATE - Override release date (default: today in UTC, YYYY-MM-DD)

set -euo pipefail

: "${TAG_NAME:?TAG_NAME is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

releases_dir="${RELEASES_DIR:-docs/src/content/docs/releases}"
version="${TAG_NAME#v}"
version_slug="${version//./-}"
release_date="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"

# Find the previous version tag for the changelog link
prev_tag="$(git tag --sort=-v:refname | grep -E '^v[0-9]' | head -2 | tail -1)"

# Increment sidebar.order for all existing version files (v*.md)
for file in "$releases_dir"/v*.md; do
  [ -f "$file" ] || continue
  current_order="$(sed -n 's/^  order: \([0-9]*\)/\1/p' "$file")"
  if [ -n "$current_order" ]; then
    new_order=$((current_order + 1))
    sed -i "s/^  order: ${current_order}/  order: ${new_order}/" "$file"
  fi
done

# Create the versioned release file from next.md
{
  echo '---'
  echo "title: v${version}"
  echo 'sidebar:'
  echo '  order: 2'
  echo '---'
  echo ""
  echo "Released on ${release_date}. [Full changelog](https://github.com/${GITHUB_REPOSITORY}/compare/${prev_tag}...${TAG_NAME})"
  echo ""

  # Append the body of next.md (skip frontmatter and the description line)
  awk '
    BEGIN { fm=0; skip_header=1 }
    fm<2 && /^---$/ { fm++; next }
    fm<2 { next }
    skip_header && /^$/ { next }
    skip_header && /^This page tracks changes/ { next }
    { skip_header=0; print }
  ' "$releases_dir/next.md"
} > "$releases_dir/v${version_slug}.md"

# Reset next.md
printf '%s\n' \
  '---' \
  'title: Next (unreleased)' \
  'sidebar:' \
  '  order: 1' \
  '---' \
  '' \
  'No unreleased changes yet.' \
  > "$releases_dir/next.md"
