# Changelog

## [0.1.1](https://github.com/fohte/runok/compare/v0.1.0...v0.1.1) (2026-02-15)


### Features

* **config:** add config validation ([#18](https://github.com/fohte/runok/issues/18)) ([9421327](https://github.com/fohte/runok/commit/94213275b78297bd46206c75fab38e633627ccda))
* **config:** support global and local config merging ([#25](https://github.com/fohte/runok/issues/25)) ([4ecb66c](https://github.com/fohte/runok/commit/4ecb66c382c14b67172806444e7a32d4e329b75d))
* **config:** support YAML config file parsing ([#6](https://github.com/fohte/runok/issues/6)) ([c1b3d64](https://github.com/fohte/runok/commit/c1b3d648459234c3e5ca8b66c7a0d8a995632972))
* define common error types for each layer ([#2](https://github.com/fohte/runok/issues/2)) ([14cb840](https://github.com/fohte/runok/commit/14cb84095d1c102d2bbedccb8d10d145b9e4b195))
* **exec:** fall back to ask on extension errors ([#24](https://github.com/fohte/runok/issues/24)) ([91395e6](https://github.com/fohte/runok/commit/91395e688291c8f3fc23e608a6d54a432896c48c))
* **exec:** support JSON-RPC 2.0 communication with extension plugins ([#19](https://github.com/fohte/runok/issues/19)) ([d30c9ab](https://github.com/fohte/runok/commit/d30c9ab81d060742412504a20f87fab8c1903908))
* **rules:** implement `LexToken`-based pattern parser ([#5](https://github.com/fohte/runok/issues/5)) ([556ef10](https://github.com/fohte/runok/commit/556ef10c0a16495c9a2b6faa6c020ce127a0972d))
* **rules:** implement CEL expression evaluator for when-clause conditions ([#8](https://github.com/fohte/runok/issues/8)) ([227252f](https://github.com/fohte/runok/commit/227252f424a3f0d03b62605ebb49fe7037795a86))
* **rules:** implement command string tokenizer ([#7](https://github.com/fohte/runok/issues/7)) ([f780588](https://github.com/fohte/runok/commit/f7805885094c17eb0dbf9754941d22ddd009c9ed))
* **rules:** implement pattern string lexer for tokenization ([#4](https://github.com/fohte/runok/issues/4)) ([397e6d8](https://github.com/fohte/runok/commit/397e6d84b7a0dd2be6df26fb8cc04459f50f171a))
* **rules:** structure command strings into flags and arguments ([#21](https://github.com/fohte/runok/issues/21)) ([47feaba](https://github.com/fohte/runok/commit/47feaba13fd5c3146d7558169bc14c640ff789c9))
* **rules:** support command extraction from subshells ([#23](https://github.com/fohte/runok/issues/23)) ([07cafa8](https://github.com/fohte/runok/commit/07cafa8c14eb40207acbca4201031ebb79548a4e))
* **rules:** support recursive command extraction from control structures ([#26](https://github.com/fohte/runok/issues/26)) ([ac7ac89](https://github.com/fohte/runok/commit/ac7ac8991fb38188ecdf06db3823d871c5c72871))


### Bug Fixes

* **config:** preserve global `definitions.paths` during config merge ([#28](https://github.com/fohte/runok/issues/28)) ([7a30d16](https://github.com/fohte/runok/commit/7a30d16bfe8f02082daac7fc2c63530f78436a89))
* resolve ETXTBSY flaky tests on Linux CI by retrying spawn ([#32](https://github.com/fohte/runok/issues/32)) ([6980503](https://github.com/fohte/runok/commit/698050368454439dd61e8cb1cb5248d84c11c0f0))


### Dependencies

* update rust crate serde_json to v1.0.149 ([#20](https://github.com/fohte/runok/issues/20)) ([98d5d1a](https://github.com/fohte/runok/commit/98d5d1a646a7ebe6cb154fe2bd58ca322a21c294))
* update rust crate serde-saphyr to v0.0.17 ([#14](https://github.com/fohte/runok/issues/14)) ([336b13d](https://github.com/fohte/runok/commit/336b13d0aec0a3f84999bde1aa4d86939b70470b))
