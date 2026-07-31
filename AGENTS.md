# AGENTS.md

## Project

- This repository provides the `github.com/elastic/go-grok` module.
- It implements a Grok parsing library based on RE2 regular expressions.
- The module declares Go 1.22.0 and toolchain Go 1.24.2.
- Default patterns live in `patterns/default.go`.
- Call `Compile` once before parsing.

## Map

- `grok.go` contains the library entry point.
- `grok_test.go` tests the core library.
- `regexp/` contains regular-expression compilation code and tests.
- `parsers/` contains supporting parsers.
- `patterns/` contains the default and optional predefined pattern sets.
- `patterns_test/` tests the predefined pattern sets.
- `benchmarks/` contains a separate benchmark module and benchmark tests.
- `dev-tools/mage/` contains Mage support code.
- `dev-tools/templates/notice/` contains dependency notice templates and rules.
- `.buildkite/` and `.github/` contain continuous-integration configuration.

## Commands

- The supplied documentation does not define a repository command.
- Use the commands defined by the repository Mage and CI files when those files are available.

## Rules

- Keep the module path `github.com/elastic/go-grok`.
- Preserve Go 1.22.0 compatibility and the Go 1.24.2 toolchain directive.
- Keep default patterns in `patterns/default.go`.
- Put optional predefined pattern sets in `patterns/*.go`.
- Add pattern-set tests under `patterns_test/`.
- Keep benchmark dependencies in the separate `benchmarks` module.
- Preserve the local Mage module replacement exactly as declared in `go.mod`.
- Update `NOTICE.txt` and its templates together when dependency notices change.
- Do not document a command unless a repository manifest, Mage file, CI file, or documentation defines it.
