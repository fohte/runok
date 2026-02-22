# Changelog

## [0.1.1](https://github.com/fohte/runok/compare/v0.1.0...v0.1.1) (2026-02-22)


### Features

* **adapter:** add `CheckAdapter` for generic check interface ([#53](https://github.com/fohte/runok/issues/53)) ([cb6dc15](https://github.com/fohte/runok/commit/cb6dc15fb636f8c74fad6c3b000cd4cc907ddf11))
* **adapter:** add `Endpoint` trait and common evaluation flow ([#51](https://github.com/fohte/runok/issues/51)) ([0aee28c](https://github.com/fohte/runok/commit/0aee28ceffa7f411921398ed0b28744a0429acea))
* **adapter:** implement `ExecAdapter` ([#52](https://github.com/fohte/runok/issues/52)) ([36e6453](https://github.com/fohte/runok/commit/36e6453212206748a6edae55caae604f05415f23))
* **adapter:** include matched rule, reason, and fix suggestion in deny feedback ([#58](https://github.com/fohte/runok/issues/58)) ([bd8f929](https://github.com/fohte/runok/commit/bd8f929bd57b0826d105ea25e2768627330a5d3f))
* **adapter:** support `Endpoint` implementation for Claude Code PreToolUse Hook ([#54](https://github.com/fohte/runok/issues/54)) ([0c0eabf](https://github.com/fohte/runok/commit/0c0eabfb6b0278dc8ee5f4b44e5f00e0927e836b))
* **cli:** add `--dry-run` and `--verbose` options to `exec`/`check` subcommands ([#59](https://github.com/fohte/runok/issues/59)) ([f2eee5e](https://github.com/fohte/runok/commit/f2eee5edfb81bf92dd9d4455ae9c3eed77eda6a5))
* **cli:** implement `exec`/`check` subcommands with stdin input routing ([#55](https://github.com/fohte/runok/issues/55)) ([041fc33](https://github.com/fohte/runok/commit/041fc339e99319d01ea2fe641cf0b611e3c81b39))
* **cli:** return spec-compliant exit codes per subcommand ([#56](https://github.com/fohte/runok/issues/56)) ([2030cbc](https://github.com/fohte/runok/commit/2030cbc75960ebf5d2bf4b7fc7bd6da165075d12))
* **cli:** support plaintext stdin input for `check` subcommand ([#57](https://github.com/fohte/runok/issues/57)) ([2efb529](https://github.com/fohte/runok/commit/2efb529ff754bf04316dd034614f6cc21e8ab8a4))
* **config:** add config validation ([#18](https://github.com/fohte/runok/issues/18)) ([9421327](https://github.com/fohte/runok/commit/94213275b78297bd46206c75fab38e633627ccda))
* **config:** detect circular references in nested extends ([#48](https://github.com/fohte/runok/issues/48)) ([00bcbe3](https://github.com/fohte/runok/commit/00bcbe3f597193abf591c0f5efeb000c2a3aee5b))
* **config:** expand `<path:name>` references in sandbox preset `fs.deny` ([#66](https://github.com/fohte/runok/issues/66)) ([3fbaf0e](https://github.com/fohte/runok/commit/3fbaf0eea3ed7d15db84b7b79a7139b0cfced16b))
* **config:** support global and local config merging ([#25](https://github.com/fohte/runok/issues/25)) ([4ecb66c](https://github.com/fohte/runok/commit/4ecb66c382c14b67172806444e7a32d4e329b75d))
* **config:** support loading local preset files from `extends` ([#36](https://github.com/fohte/runok/issues/36)) ([6b5e3cf](https://github.com/fohte/runok/commit/6b5e3cf0df2fb7135ce546da3f43fdbee4d26602))
* **config:** support remote preset resolution via `git clone --depth 1` ([#43](https://github.com/fohte/runok/issues/43)) ([5368ddb](https://github.com/fohte/runok/commit/5368ddb410d40ef17a40cbe4dc4cd5800939d91e))
* **config:** support YAML config file parsing ([#6](https://github.com/fohte/runok/issues/6)) ([c1b3d64](https://github.com/fohte/runok/commit/c1b3d648459234c3e5ca8b66c7a0d8a995632972))
* define common error types for each layer ([#2](https://github.com/fohte/runok/issues/2)) ([14cb840](https://github.com/fohte/runok/commit/14cb84095d1c102d2bbedccb8d10d145b9e4b195))
* **exec:** add dry-run mode to `CommandExecutor` ([#41](https://github.com/fohte/runok/issues/41)) ([77eb8ce](https://github.com/fohte/runok/commit/77eb8ced2adac4f064d9ebe21d6b6d18000a849a))
* **exec:** fall back to ask on extension errors ([#24](https://github.com/fohte/runok/issues/24)) ([91395e6](https://github.com/fohte/runok/commit/91395e688291c8f3fc23e608a6d54a432896c48c))
* **exec:** support command execution with exit code forwarding via `CommandExecutor` ([#38](https://github.com/fohte/runok/issues/38)) ([5c04095](https://github.com/fohte/runok/commit/5c040955c10f808fd2b941d0b9769f7bd9a884a1))
* **exec:** support JSON-RPC 2.0 communication with extension plugins ([#19](https://github.com/fohte/runok/issues/19)) ([d30c9ab](https://github.com/fohte/runok/commit/d30c9ab81d060742412504a20f87fab8c1903908))
* **rules:** add pattern-to-command matching engine ([#37](https://github.com/fohte/runok/issues/37)) ([823d96b](https://github.com/fohte/runok/commit/823d96b6236eebe4560c0624e15e95cd45cb5f83))
* **rules:** add rule engine with Explicit Deny Wins priority ([#40](https://github.com/fohte/runok/issues/40)) ([28834e5](https://github.com/fohte/runok/commit/28834e5ba503e8ee50e267069df5d040a8dd1d4b))
* **rules:** implement `LexToken`-based pattern parser ([#5](https://github.com/fohte/runok/issues/5)) ([556ef10](https://github.com/fohte/runok/commit/556ef10c0a16495c9a2b6faa6c020ce127a0972d))
* **rules:** implement CEL expression evaluator for when-clause conditions ([#8](https://github.com/fohte/runok/issues/8)) ([227252f](https://github.com/fohte/runok/commit/227252f424a3f0d03b62605ebb49fe7037795a86))
* **rules:** implement command string tokenizer ([#7](https://github.com/fohte/runok/issues/7)) ([f780588](https://github.com/fohte/runok/commit/f7805885094c17eb0dbf9754941d22ddd009c9ed))
* **rules:** implement pattern string lexer for tokenization ([#4](https://github.com/fohte/runok/issues/4)) ([397e6d8](https://github.com/fohte/runok/commit/397e6d84b7a0dd2be6df26fb8cc04459f50f171a))
* **rules:** structure command strings into flags and arguments ([#21](https://github.com/fohte/runok/issues/21)) ([47feaba](https://github.com/fohte/runok/commit/47feaba13fd5c3146d7558169bc14c640ff789c9))
* **rules:** support command extraction from subshells ([#23](https://github.com/fohte/runok/issues/23)) ([07cafa8](https://github.com/fohte/runok/commit/07cafa8c14eb40207acbca4201031ebb79548a4e))
* **rules:** support compound command evaluation with result aggregation ([#49](https://github.com/fohte/runok/issues/49)) ([4395c0b](https://github.com/fohte/runok/commit/4395c0bd728d3a07db6da781ef1dd0b0d05c8461))
* **rules:** support recursive command extraction from control structures ([#26](https://github.com/fohte/runok/issues/26)) ([ac7ac89](https://github.com/fohte/runok/commit/ac7ac8991fb38188ecdf06db3823d871c5c72871))
* **rules:** support recursive wrapper command evaluation ([#45](https://github.com/fohte/runok/issues/45)) ([c6fd568](https://github.com/fohte/runok/commit/c6fd5684fd1e5ce81aa275093fdc4d5378415171))
* **sandbox:** implement `SandboxPolicy` construction and policy resolution ([#63](https://github.com/fohte/runok/issues/63)) ([a77bcca](https://github.com/fohte/runok/commit/a77bccaab3394f49175761c16c502b05e9a2b2b4))
* **sandbox:** implement Linux sandbox helper binary ([#68](https://github.com/fohte/runok/issues/68)) ([545ae31](https://github.com/fohte/runok/commit/545ae31c3cf42c8c2f14a45f1c276a48742c8d73))


### Bug Fixes

* **config:** preserve global `definitions.paths` during config merge ([#28](https://github.com/fohte/runok/issues/28)) ([7a30d16](https://github.com/fohte/runok/commit/7a30d16bfe8f02082daac7fc2c63530f78436a89))
* resolve ETXTBSY flaky tests on Linux CI by retrying spawn ([#32](https://github.com/fohte/runok/issues/32)) ([6980503](https://github.com/fohte/runok/commit/698050368454439dd61e8cb1cb5248d84c11c0f0))


### Dependencies

* update rust crate clap to v4.5.58 ([#47](https://github.com/fohte/runok/issues/47)) ([fca519c](https://github.com/fohte/runok/commit/fca519c4fb41a43eea71161fd851d34d20248232))
* update rust crate landlock to v0.4.4 ([#69](https://github.com/fohte/runok/issues/69)) ([9abbb8d](https://github.com/fohte/runok/commit/9abbb8d940cbc03906995de918059fffca773f6d))
* update rust crate serde_json to v1.0.149 ([#20](https://github.com/fohte/runok/issues/20)) ([98d5d1a](https://github.com/fohte/runok/commit/98d5d1a646a7ebe6cb154fe2bd58ca322a21c294))
* update rust crate serde-saphyr to v0.0.17 ([#14](https://github.com/fohte/runok/issues/14)) ([336b13d](https://github.com/fohte/runok/commit/336b13d0aec0a3f84999bde1aa4d86939b70470b))
* update rust crate serde-saphyr to v0.0.18 ([#42](https://github.com/fohte/runok/issues/42)) ([ea3bad4](https://github.com/fohte/runok/commit/ea3bad46cdfdff43e65af69cc201abdfabf0ec28))
* update rust crate serde-saphyr to v0.0.19 ([#70](https://github.com/fohte/runok/issues/70)) ([aa6e315](https://github.com/fohte/runok/commit/aa6e315b300f34a9ab156d993ca2c3551d07da21))
* update rust crate sha2 to v0.10.9 ([#46](https://github.com/fohte/runok/issues/46)) ([62c8316](https://github.com/fohte/runok/commit/62c8316d957b05f7a9ecd1f74ca864c21b58fb07))
