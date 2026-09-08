#!/bin/bash
# Fail the build if anything that looks like console key material is tracked in git.
#
# This is a backstop, not the defence -- the defence is that no key is ever written into a
# source file in the first place (see NOTICE.md). It exists because the one mistake this
# project cannot take back is a key reaching public history.
set -uo pipefail
fail=0

report() { echo "::error::$1"; fail=1; }

# 1. a GodMode9 keyslot dump, in any file. No file is exempt: lp_keys.py builds its
#    throwaway slots at run time and has no 32-hex literal in it.
if git grep -lIE 'slot0x[0-9A-Fa-f]{2}Key[XYN][[:space:]]*=[[:space:]]*[0-9A-Fa-f]{32}' \
       -- . ':!.github/scripts/keyscan.sh' >/dev/null 2>&1; then
  report "a keyslot dump appears to be committed:"
  git grep -nIE 'slot0x[0-9A-Fa-f]{2}Key[XYN][[:space:]]*=[[:space:]]*[0-9A-Fa-f]{32}' \
      -- . ':!.github/scripts/keyscan.sh'
fi

# 2. a cecd HMAC key string written out as a literal.
#    lp_keys.py legitimately contains two: the generated throwaway pair that install_test_keys
#    writes so the suite can run with no console dump. Those two exact strings are allowed and
#    NOTHING else is -- an exemption for the whole file would be a hole in this check.
if git grep -hIE 'cecd_hmac_(retail|dev)[[:space:]]*=[[:space:]]*"[^"]+"' -- . \
     ':!.github/scripts/keyscan.sh' \
   | grep -vE '"(LinuxPassSelfTes|LinuxPassSelfDev)"' \
   | grep -q .; then
  report "a cecd HMAC key string that is not the known throwaway pair is committed:"
  git grep -nIE 'cecd_hmac_(retail|dev)[[:space:]]*=[[:space:]]*"[^"]+"' -- . \
       ':!.github/scripts/keyscan.sh' \
    | grep -vE '"(LinuxPassSelfTes|LinuxPassSelfDev)"'
fi

# 3. the key files themselves, however they got in
for f in aes_keys.txt linuxpass.keys; do
  if git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    report "$f is tracked in git"
  fi
done

# 4. console dumps and captures
if git ls-files | grep -qE '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'; then
  report "a binary dump or capture is tracked in git:"
  git ls-files | grep -E '\.(pcap|pcapng|bin|i64|cxi|cia|3ds|3dsx|app|tmd)$'
fi

if [ "$fail" -eq 0 ]; then
  echo "clean: no key material, dumps or captures are tracked"
fi
exit "$fail"
