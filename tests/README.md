# tests/

`tests/corpus/` is where you put your own captures and console dumps if you want to run the
self-tests' hardware regressions. It is git-ignored, and CI fails the build if anything in it
is ever tracked.

See the wiki page *Running the self-tests* for the `manifest.json` and `vectors.json` shapes.

Nothing here is needed to run LinuxPass, or to run the self-test suite — a clone with an empty
corpus passes, and reports `[SKIP]` for the checks that would have used one.
