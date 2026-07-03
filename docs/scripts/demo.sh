#!/bin/sh
# Regenerate docs/assets/demo.png from a real run of `cookiesync doctor`.
#
# Requires freeze (brew install charmbracelet/tap/freeze) and an installed
# cookiesync. Re-run whenever doctor's output shape changes. The demo is
# doctor on purpose: it proves the install without rendering a single
# cookie value or header.
set -eu
cd "$(dirname "$0")/../.."

freeze \
  --execute 'sh -c "echo \"$ cookiesync doctor\"; cookiesync doctor 2>&1"' \
  --theme github-dark \
  --background "#0d1117" \
  --window \
  --padding 24 \
  --font.size 28 \
  --wrap 80 \
  --output docs/assets/demo.png
