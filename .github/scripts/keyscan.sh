#!/bin/bash
# Fail the build if anything that looks like console key material is tracked in git.
set -uo pipefail
fail=0

report() { echo "::error::$1"; fail=1; }

# A GodMode9 keyslot dump, in any file.
if git grep -lIE 'slot0x[0-9A-Fa-f]{2}Key[XYN][[:space:]]*=[[:space:]]*[0-9A-Fa-f]{32}' \
       -- . ':!.github/scripts/keyscan.sh' >/dev/null 2>&1; then
  report "a keyslot dump appears to be committed:"
  git grep -nIE 'slot0x[0-9A-Fa-f]{2}Key[XYN][[:space:]]*=[[:space:]]*[0-9A-Fa-f]{32}' \
      -- . ':!.github/scripts/keyscan.sh'
fi

# A cecd HMAC key string as a literal. Only the known throwaway pair is allowed.
if git grep -hIE 'cecd_hmac_(retail|dev)[[:space:]]*=[[:space:]]*"[^"]+"' -- . \
     ':!.github/scripts/keyscan.sh' \
   | grep -vE '"(LinuxPassSelfTes|LinuxPassSelfDev)"' \
   | grep -q .; then
  report "a cecd HMAC key string that is not the known throwaway pair is committed:"
  git grep -nIE 'cecd_hmac_(retail|dev)[[:space:]]*=[[:space:]]*"[^"]+"' -- . \
       ':!.github/scripts/keyscan.sh' \
    | grep -vE '"(LinuxPassSelfTes|LinuxPassSelfDev)"'
fi

# The key files themselves.
for f in aes_keys.txt linuxpass.keys; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    report "$f is tracked in git"
  fi
done

# Console dumps and captures.
if git ls-files | grep -qE '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'; then
  report "a binary dump or capture is tracked in git:"
  git ls-files | grep -E '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'
fi

if [ "$fail" -eq 0 ]; then
  echo "clean: no key material, dumps or captures are tracked"
fi
exit "$fail"
