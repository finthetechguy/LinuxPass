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

# A bare 32-byte key written as hex. The rows of the public AES S-box are the only exception.
ALLOWED_HEX='637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0
b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275
09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf
d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2
cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb
e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08
ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e
e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
bare=$(git grep -IlE '[0-9A-Fa-f]{64}' -- . ':!.github/scripts/keyscan.sh' 2>/dev/null \
  | while IFS= read -r f; do
      grep -noE '[0-9A-Fa-f]{64,}' "$f" | awk -F: -v f="$f" -v allow="$ALLOWED_HEX" '
        BEGIN { n = split(allow, a, "\n"); for (i = 1; i <= n; i++) ok[a[i]] = 1 }
        length($2) == 64 && !($2 in ok) { print f ":" $1 }'
    done)
if [ -n "$bare" ]; then
  report "a 64-digit hex value that could be a 32-byte key is tracked (values not shown):"
  printf '%s\n' "$bare"
fi

# The key files themselves, anywhere in the tree.
keyfiles=$(git ls-files | grep -iE '(^|/)aes_keys\.txt$|\.keys?$')
if [ -n "$keyfiles" ]; then
  report "a key file is tracked in git:"
  printf '%s\n' "$keyfiles"
fi

# Console dumps and captures.
if git ls-files | grep -qE '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'; then
  report "a binary dump or capture is tracked in git:"
  git ls-files | grep -E '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'
fi

if [ "$fail" -eq 0 ]; then
  echo "clean: no key material, dumps or captures are tracked"
fi
exit "$fail"
