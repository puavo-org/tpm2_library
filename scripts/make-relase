#!/bin/sh
# Copyright (c) 2025 Opinsys Oy

PREVIOUS="${1:-$PREV}"
NEXT="${2:-$NEXT}"

if [ -z "$NEXT" ] || [ -z "$PREVIOUS" ]; then
  echo "Usage: $0 <PREVIOUS> <NEXT>"
  exit 1
fi

MESSAGE=$(
  echo "Release $NEXT"
  echo ""
  git log --pretty=format:"- %s" --no-merges "$PREVIOUS..HEAD"
)

printf "%s" "$MESSAGE" | git tag -s "$NEXT" -F -
