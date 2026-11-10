# tests/

`tests/corpus/` is where you put your own captures and console dumps if you want to run the
self-tests' hardware regressions. It is git-ignored, and CI fails the build if a capture or dump
file type is tracked anywhere in the repository.

The wiki page *Running the self-tests* shows the `manifest.json` and `vectors.json` formats.

You do not need anything here to run LinuxPass or the self-test suite. A clone with an empty
corpus passes, and reports `[SKIP]` for the checks that would have used one.
