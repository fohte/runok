# Changelog

## [0.2.2](https://github.com/fohte/runok/compare/v0.2.1...v0.2.2) (2026-04-12)


### Features

* **config:** declare version guards with `required_runok_version` ([#299](https://github.com/fohte/runok/issues/299)) ([2990a0e](https://github.com/fohte/runok/commit/2990a0e3463013ab1c0ead5c29648701142ef887))
* **rules:** add `<flag:name>` placeholder to inspect every value of repeated and aliased flags in `when` clauses ([#278](https://github.com/fohte/runok/issues/278)) ([2fe0c76](https://github.com/fohte/runok/commit/2fe0c766ee6eeecfceee2a2be5d2746299ec3516))


### Bug Fixes

* **rules:** evaluate subshell-wrapped arguments through the wrapper path ([#297](https://github.com/fohte/runok/issues/297)) ([5afc9c8](https://github.com/fohte/runok/commit/5afc9c85be0911dafa1530095360d34064151950))


### Dependencies

* update rust crate libc to v0.2.184 ([#279](https://github.com/fohte/runok/issues/279)) ([474b911](https://github.com/fohte/runok/commit/474b911de3b6ed48422ca6501287b239abbb06d9))
* update rust crate semver to v1.0.28 ([#295](https://github.com/fohte/runok/issues/295)) ([a6ef431](https://github.com/fohte/runok/commit/a6ef43158a1bb6107519dc386abb0a97b885f154))
* update rust crate serde-saphyr to v0.0.23 ([#282](https://github.com/fohte/runok/issues/282)) ([addc72d](https://github.com/fohte/runok/commit/addc72d8a2d9e6c8fd383501f84a1ff88054240f))
* update rust crate sha2 to v0.11.0 ([#272](https://github.com/fohte/runok/issues/272)) ([5cdf128](https://github.com/fohte/runok/commit/5cdf128d68f4e95df599cb9b8081a52cf6e5425d))
* update rust crate tree-sitter to v0.26.8 ([#283](https://github.com/fohte/runok/issues/283)) ([35e011b](https://github.com/fohte/runok/commit/35e011bbe4477762bd5b19a837fe414cd5c1a2b1))

## [0.2.1](https://github.com/fohte/runok/compare/v0.2.0...v0.2.1) (2026-04-03)


### Features

* **cli:** support `runok migrate` command to auto-convert deprecated sandbox fs config ([#252](https://github.com/fohte/runok/issues/252)) ([3dccd3e](https://github.com/fohte/runok/commit/3dccd3e75cb101b8d2e5d03accd4a122db0e66ab))
* **sandbox:** support read/write sub-sections in sandbox fs config with read denial ([#236](https://github.com/fohte/runok/issues/236)) ([9f06e51](https://github.com/fohte/runok/commit/9f06e5158abbd92e167cefe016fcf50e26a50bc2))


### Bug Fixes

* **command_parser:** handle `negated_command` as a transparent container ([#266](https://github.com/fohte/runok/issues/266)) ([3aebc80](https://github.com/fohte/runok/commit/3aebc80e8c56b04d2010360d0eb9fe4a14104e0a))
* **config:** add `runok warning:` prefix and config file path to deprecation warnings ([#242](https://github.com/fohte/runok/issues/242)) ([1706f2e](https://github.com/fohte/runok/commit/1706f2e58546f55a4d636bca1b0819076658ec9c))
* **config:** remove unused `definitions.commands` field ([#235](https://github.com/fohte/runok/issues/235)) ([31ebb2c](https://github.com/fohte/runok/commit/31ebb2c565d25407a51003af10e037cb9a7b338d))
* **test:** strip inline tests from remote presets on load ([#227](https://github.com/fohte/runok/issues/227)) ([725cf6e](https://github.com/fohte/runok/commit/725cf6e1a52890bd440ee89159bec55b895b7d5e))


### Dependencies

* update rust crate clap to v4.5.61 ([#241](https://github.com/fohte/runok/issues/241)) ([42992c9](https://github.com/fohte/runok/commit/42992c9177e1b92b81a210da26b6cc0b54eaeb81))
* update rust crate clap to v4.6.0 ([#245](https://github.com/fohte/runok/issues/245)) ([39cd8c8](https://github.com/fohte/runok/commit/39cd8c8de5d6ab80273ca06d3f6b2f7adb1b6f75))
* update rust crate libc to v0.2.183 ([#220](https://github.com/fohte/runok/issues/220)) ([22e7f27](https://github.com/fohte/runok/commit/22e7f2766d72c600048a798aa48ee86c715c5fac))
* update rust crate serde-saphyr to v0.0.22 ([#259](https://github.com/fohte/runok/issues/259)) ([123c2f1](https://github.com/fohte/runok/commit/123c2f196c8dfb473e835f98551249f0c0fd4763))
* update rust crate terminal_size to v0.4.4 ([#268](https://github.com/fohte/runok/issues/268)) ([14a436a](https://github.com/fohte/runok/commit/14a436ad6c504f6b0535668373d2b30032143f0f))
* update rust crate tree-sitter to v0.26.7 ([#254](https://github.com/fohte/runok/issues/254)) ([983c835](https://github.com/fohte/runok/commit/983c8351198bc4294e574f4e3e943f5c3ba057bb))

## [0.2.0](https://github.com/fohte/runok/compare/v0.1.5...v0.2.0) (2026-03-15)


### ⚠ BREAKING CHANGES

* treat `*` inside quotes as glob, support `\*` escape for literal asterisk ([#157](https://github.com/fohte/runok/issues/157))

### Features

* **audit:** improve `audit` subcommand output with table format and colors ([#200](https://github.com/fohte/runok/issues/200)) ([490e206](https://github.com/fohte/runok/commit/490e206ced957e86d3fd153c4ff59d761635ec2c))
* **audit:** support audit logging for command evaluation results ([#103](https://github.com/fohte/runok/issues/103)) ([25c6749](https://github.com/fohte/runok/commit/25c6749ea560a4d18711e167f0d4c00fa623c916))
* **cli:** add `--dir` filter option to `runok audit` ([#207](https://github.com/fohte/runok/issues/207)) ([71b768e](https://github.com/fohte/runok/commit/71b768eb02f21009b39aa33a8f4d65e168c20c80))
* **cli:** add `runok test` subcommand for rule verification ([#204](https://github.com/fohte/runok/issues/204)) ([cfafb18](https://github.com/fohte/runok/commit/cfafb18bb5ca9433a7b8cac24fdbd431eb89e215))
* **cli:** add `update-presets` command ([#197](https://github.com/fohte/runok/issues/197)) ([4c57355](https://github.com/fohte/runok/commit/4c5735573911666990a27f37ba887ec19158b3a5))
* **rules:** add typed variable definitions (`definitions.vars`) with `<var:name>` placeholder ([#201](https://github.com/fohte/runok/issues/201)) ([ffee2ec](https://github.com/fohte/runok/commit/ffee2ec6d5f00b1c5d8a0ccc19e235d1a9f63a96))
* **rules:** support `<var:name>` in command position and per-value type ([#208](https://github.com/fohte/runok/issues/208)) ([c5995ae](https://github.com/fohte/runok/commit/c5995ae7200a840b044137b80bece15443a3373e))
* **rules:** support `redirects` and `pipe` variables in `when` clauses ([#203](https://github.com/fohte/runok/issues/203)) ([a513e1b](https://github.com/fohte/runok/commit/a513e1b3d5d6eee01d35c890da1dab4b52f95154))
* **rules:** support fused short flag pattern matching (`-n3`) ([#205](https://github.com/fohte/runok/issues/205)) ([7a74122](https://github.com/fohte/runok/commit/7a7412289ade904add947f19ad934b9fe218e3cf))
* treat `*` inside quotes as glob, support `\*` escape for literal asterisk ([#157](https://github.com/fohte/runok/issues/157)) ([23c7789](https://github.com/fohte/runok/commit/23c7789fa8abaa50c6190f241f00cc5fac15a9e8))


### Bug Fixes

* **cli:** reject unknown flags before `--` in `exec`/`check` subcommands ([#202](https://github.com/fohte/runok/issues/202)) ([7344abd](https://github.com/fohte/runok/commit/7344abd133defc254e9e6aa78c890a869e62b0c3))
* **cli:** remove `exec --dry-run` option ([#216](https://github.com/fohte/runok/issues/216)) ([155c0d3](https://github.com/fohte/runok/commit/155c0d30ad5bf13b4d727b9f86dd7f536ff38dc2))
* **pattern-matcher:** skip flag-starting token sequences in `<cmd>` placeholder matching ([#206](https://github.com/fohte/runok/issues/206)) ([f706488](https://github.com/fohte/runok/commit/f7064883def3bf9c0bc875e9e1ae0a13289171f2))


### Dependencies

* update rust crate chrono to v0.4.44 ([#211](https://github.com/fohte/runok/issues/211)) ([68bdb28](https://github.com/fohte/runok/commit/68bdb2830f49c433e9ef3cbe8c8f748d20ff3108))
* update rust crate semver to v1.0.27 ([#212](https://github.com/fohte/runok/issues/212)) ([81a5251](https://github.com/fohte/runok/commit/81a525147e3145b222199429e0ef4c8e13c52fec))

## [0.1.5](https://github.com/fohte/runok/compare/v0.1.4...v0.1.5) (2026-03-12)


### Bug Fixes

* **rules:** handle `=`-joined flag tokens in Alternation matching ([#196](https://github.com/fohte/runok/issues/196)) ([15fe774](https://github.com/fohte/runok/commit/15fe77484a6df1fe07f3edc1e9d6f470838c4284))
* **rules:** prevent flag negation from being consumed as preceding flag's value ([#191](https://github.com/fohte/runok/issues/191)) ([31b76a8](https://github.com/fohte/runok/commit/31b76a827be23f1bb62d9ba031222e04d444b10b))

## [0.1.4](https://github.com/fohte/runok/compare/v0.1.3...v0.1.4) (2026-03-11)


### Features

* **init:** warn when other PreToolUse hooks conflict with runok sandbox ([#186](https://github.com/fohte/runok/issues/186)) ([94a506f](https://github.com/fohte/runok/commit/94a506faa5601019e36a2855563f4720aa1f8052))
* **rules:** apply order-independent matching to literal tokens ([#177](https://github.com/fohte/runok/issues/177)) ([e257cad](https://github.com/fohte/runok/commit/e257cadb91d097583448136d78c30a4945efbeb0))


### Bug Fixes

* **rules:** allow flag-only negation to pass with empty command tokens ([#179](https://github.com/fohte/runok/issues/179)) ([1d6c757](https://github.com/fohte/runok/commit/1d6c757106fe2b9bd021c9fb88301954c0c2c059))
* **rules:** match `FlagWithValue` patterns against `=`-joined tokens ([#180](https://github.com/fohte/runok/issues/180)) ([6ebb296](https://github.com/fohte/runok/commit/6ebb2962929dcfd381e0a61e1b939f43fa577d22))
* **rules:** match flag-only negation patterns against `=`-joined tokens ([#175](https://github.com/fohte/runok/issues/175)) ([7cf8eaa](https://github.com/fohte/runok/commit/7cf8eaaa34fa67b2a7d192f61102b507df105d79))
* **rules:** resolve unmatched sub-commands to concrete actions in compound evaluation ([#178](https://github.com/fohte/runok/issues/178)) ([377f83d](https://github.com/fohte/runok/commit/377f83d5936544987ba17d7d0fcdac6514863d1e))

## [0.1.3](https://github.com/fohte/runok/compare/v0.1.2...v0.1.3) (2026-03-09)


### Features

* **config:** resolve relative paths based on config file parent directory ([#166](https://github.com/fohte/runok/issues/166)) ([ee1a7c3](https://github.com/fohte/runok/commit/ee1a7c33042631b28b651af34ad1aa63af414a5d))
* **preset:** add file-based locking for concurrent preset cache access ([#168](https://github.com/fohte/runok/issues/168)) ([27c31f4](https://github.com/fohte/runok/commit/27c31f46fba8adc4fe015b61264aef8a62ec6dc0))
* **preset:** support path specification in GitHub shorthand references ([#167](https://github.com/fohte/runok/issues/167)) ([eff4b56](https://github.com/fohte/runok/commit/eff4b56fdb28ae717811edbc551abace11fb2b81))


### Bug Fixes

* **config:** resolve preset rules referenced via `extends` ([#174](https://github.com/fohte/runok/issues/174)) ([abc5e41](https://github.com/fohte/runok/commit/abc5e412a57854485ff497037b45415afa9f86dc))
* **config:** traverse ancestor directories to find project config ([#165](https://github.com/fohte/runok/issues/165)) ([a49f916](https://github.com/fohte/runok/commit/a49f916bb2c49c9b6efdaa71ada36b663b03f5ab))
* **preset:** remove unnecessary mutable reference warning ([#169](https://github.com/fohte/runok/issues/169)) ([c1d9d3c](https://github.com/fohte/runok/commit/c1d9d3cee1bb729400e567324118a7b0bfc0d950))
* **rules:** apply order-independent matching to flag-only negation patterns ([#171](https://github.com/fohte/runok/issues/171)) ([9c43c91](https://github.com/fohte/runok/commit/9c43c91fbc6e8a5196fe5d15b33121afa3f4d483))


### Dependencies

* update rust crate serde-saphyr to v0.0.21 ([#162](https://github.com/fohte/runok/issues/162)) ([56c0827](https://github.com/fohte/runok/commit/56c0827f97900583b89a5b2f162f0fa87eacfd5f))

## [0.1.2](https://github.com/fohte/runok/compare/v0.1.1...v0.1.2) (2026-03-06)


### Features

* **init:** add `runok init` subcommand ([#152](https://github.com/fohte/runok/issues/152)) ([176d9b6](https://github.com/fohte/runok/commit/176d9b6c12ccb0a987ed721b264dcb6971d42278))


### Bug Fixes

* evaluate command substitutions nested in quoted strings ([#151](https://github.com/fohte/runok/issues/151)) ([af784b6](https://github.com/fohte/runok/commit/af784b6c6e5325da97bf8e69465f1d4a59519a66))
* resolve stack overflow in compound command evaluation with command substitutions ([#149](https://github.com/fohte/runok/issues/149)) ([97b46a7](https://github.com/fohte/runok/commit/97b46a7ae1903598f068cabbb3250ff3a2c3933a))
* **rules:** stop flag alternation from consuming placeholder as flag value ([#154](https://github.com/fohte/runok/issues/154)) ([24a951a](https://github.com/fohte/runok/commit/24a951a00ef83adc4748b9e260dd2889b92edb81))
* treat `--` as a positional literal instead of a flag ([#153](https://github.com/fohte/runok/issues/153)) ([c2f6d72](https://github.com/fohte/runok/commit/c2f6d726f2ca697b89e4ba993c5b36fd68a1f02e))


### Dependencies

* update rust crate dialoguer to v0.12.0 ([#158](https://github.com/fohte/runok/issues/158)) ([9e3cd2e](https://github.com/fohte/runok/commit/9e3cd2e44ed4b88bde8eff800fd96592339ef381))
* update rust crate tempfile to v3.26.0 ([#147](https://github.com/fohte/runok/issues/147)) ([02fba8a](https://github.com/fohte/runok/commit/02fba8a6909cf363a1a4c52db5f0a60e1447353d))
* update rust crate tree-sitter to v0.26.6 ([#156](https://github.com/fohte/runok/issues/156)) ([f44c9a6](https://github.com/fohte/runok/commit/f44c9a652e81121e50df8dd7de42dd5c758f2a25))

## [0.1.1](https://github.com/fohte/runok/compare/v0.1.0...v0.1.1) (2026-03-02)


### Bug Fixes

* **cli:** add `--version` flag ([#138](https://github.com/fohte/runok/issues/138)) ([a284a3b](https://github.com/fohte/runok/commit/a284a3b2e152a016a7aabd807b24c378b615dba6))
* **config:** support `runok.yaml` for global config file discovery ([#141](https://github.com/fohte/runok/issues/141)) ([b338d30](https://github.com/fohte/runok/commit/b338d30edf71a93cb58dce6d3e3202bba5ac6f8c))


### Dependencies

* update pnpm to v10.30.1 ([#133](https://github.com/fohte/runok/issues/133)) ([94023f8](https://github.com/fohte/runok/commit/94023f8015f706da3022597b710e257f5dd0b6d1))
* update rust crate tree-sitter to v0.26.5 ([#16](https://github.com/fohte/runok/issues/16)) ([4287cb2](https://github.com/fohte/runok/commit/4287cb2ffba0811eb709d51dcdbc9c4d71da525d))

## [0.1.0](https://github.com/fohte/runok/compare/v0.1.0...v0.1.0) (2026-03-01)


* trigger initial release ([c9f190c](https://github.com/fohte/runok/commit/c9f190c9ea72108573872776447e3d312cdb8986))


### Features

* **adapter:** add `CheckAdapter` for generic check interface ([#53](https://github.com/fohte/runok/issues/53)) ([cb6dc15](https://github.com/fohte/runok/commit/cb6dc15fb636f8c74fad6c3b000cd4cc907ddf11))
* **adapter:** add `Endpoint` trait and common evaluation flow ([#51](https://github.com/fohte/runok/issues/51)) ([0aee28c](https://github.com/fohte/runok/commit/0aee28ceffa7f411921398ed0b28744a0429acea))
* **adapter:** implement `ExecAdapter` ([#52](https://github.com/fohte/runok/issues/52)) ([36e6453](https://github.com/fohte/runok/commit/36e6453212206748a6edae55caae604f05415f23))
* **adapter:** include matched rule, reason, and fix suggestion in deny feedback ([#58](https://github.com/fohte/runok/issues/58)) ([bd8f929](https://github.com/fohte/runok/commit/bd8f929bd57b0826d105ea25e2768627330a5d3f))
* **adapter:** support `Endpoint` implementation for Claude Code PreToolUse Hook ([#54](https://github.com/fohte/runok/issues/54)) ([0c0eabf](https://github.com/fohte/runok/commit/0c0eabfb6b0278dc8ee5f4b44e5f00e0927e836b))
* **cli:** add `--dry-run` and `--verbose` options to `exec`/`check` subcommands ([#59](https://github.com/fohte/runok/issues/59)) ([f2eee5e](https://github.com/fohte/runok/commit/f2eee5edfb81bf92dd9d4455ae9c3eed77eda6a5))
* **cli:** add `--output-format` option and rename `--format` to `--input-format` ([#95](https://github.com/fohte/runok/issues/95)) ([5fc9592](https://github.com/fohte/runok/commit/5fc95927d6e3222704ec8184e8cbacebc6060dc4))
* **cli:** implement `exec`/`check` subcommands with stdin input routing ([#55](https://github.com/fohte/runok/issues/55)) ([041fc33](https://github.com/fohte/runok/commit/041fc339e99319d01ea2fe641cf0b611e3c81b39))
* **cli:** return spec-compliant exit codes per subcommand ([#56](https://github.com/fohte/runok/issues/56)) ([2030cbc](https://github.com/fohte/runok/commit/2030cbc75960ebf5d2bf4b7fc7bd6da165075d12))
* **cli:** support plaintext stdin input for `check` subcommand ([#57](https://github.com/fohte/runok/issues/57)) ([2efb529](https://github.com/fohte/runok/commit/2efb529ff754bf04316dd034614f6cc21e8ab8a4))
* **cli:** unify `check` command input to positional args matching `exec` ([#96](https://github.com/fohte/runok/issues/96)) ([e5a3f8f](https://github.com/fohte/runok/commit/e5a3f8fbc460c8a4657651d2b54c675212701263))
* **config:** add config validation ([#18](https://github.com/fohte/runok/issues/18)) ([9421327](https://github.com/fohte/runok/commit/94213275b78297bd46206c75fab38e633627ccda))
* **config:** detect circular references in nested extends ([#48](https://github.com/fohte/runok/issues/48)) ([00bcbe3](https://github.com/fohte/runok/commit/00bcbe3f597193abf591c0f5efeb000c2a3aee5b))
* **config:** expand `<path:name>` references in sandbox preset `fs.deny` ([#66](https://github.com/fohte/runok/issues/66)) ([3fbaf0e](https://github.com/fohte/runok/commit/3fbaf0eea3ed7d15db84b7b79a7139b0cfced16b))
* **config:** generate JSON Schema for runok.yml via `config-schema` feature ([#93](https://github.com/fohte/runok/issues/93)) ([beacb7f](https://github.com/fohte/runok/commit/beacb7fdac9dff9c9c07cd3c68d14a7ee411765c))
* **config:** prefer `$XDG_CONFIG_HOME` for global config directory ([#118](https://github.com/fohte/runok/issues/118)) ([ff30229](https://github.com/fohte/runok/commit/ff30229b393c3e61860fdcfb8ac25dabb06c5f14))
* **config:** support global and local config merging ([#25](https://github.com/fohte/runok/issues/25)) ([4ecb66c](https://github.com/fohte/runok/commit/4ecb66c382c14b67172806444e7a32d4e329b75d))
* **config:** support global local override via `runok.local.yml` ([#105](https://github.com/fohte/runok/issues/105)) ([c9091d3](https://github.com/fohte/runok/commit/c9091d3197097ccf433e979c7f85cf78f05069de))
* **config:** support loading local preset files from `extends` ([#36](https://github.com/fohte/runok/issues/36)) ([6b5e3cf](https://github.com/fohte/runok/commit/6b5e3cf0df2fb7135ce546da3f43fdbee4d26602))
* **config:** support per-project personal config override via `runok.local.yml` ([#89](https://github.com/fohte/runok/issues/89)) ([bb9e03a](https://github.com/fohte/runok/commit/bb9e03a45664a7e6d498b6ac5b9618022db268ac))
* **config:** support remote preset resolution via `git clone --depth 1` ([#43](https://github.com/fohte/runok/issues/43)) ([5368ddb](https://github.com/fohte/runok/commit/5368ddb410d40ef17a40cbe4dc4cd5800939d91e))
* **config:** support YAML config file parsing ([#6](https://github.com/fohte/runok/issues/6)) ([c1b3d64](https://github.com/fohte/runok/commit/c1b3d648459234c3e5ca8b66c7a0d8a995632972))
* define common error types for each layer ([#2](https://github.com/fohte/runok/issues/2)) ([14cb840](https://github.com/fohte/runok/commit/14cb84095d1c102d2bbedccb8d10d145b9e4b195))
* **exec:** add dry-run mode to `CommandExecutor` ([#41](https://github.com/fohte/runok/issues/41)) ([77eb8ce](https://github.com/fohte/runok/commit/77eb8ced2adac4f064d9ebe21d6b6d18000a849a))
* **exec:** fall back to ask on extension errors ([#24](https://github.com/fohte/runok/issues/24)) ([91395e6](https://github.com/fohte/runok/commit/91395e688291c8f3fc23e608a6d54a432896c48c))
* **exec:** support command execution with exit code forwarding via `CommandExecutor` ([#38](https://github.com/fohte/runok/issues/38)) ([5c04095](https://github.com/fohte/runok/commit/5c040955c10f808fd2b941d0b9769f7bd9a884a1))
* **exec:** support JSON-RPC 2.0 communication with extension plugins ([#19](https://github.com/fohte/runok/issues/19)) ([d30c9ab](https://github.com/fohte/runok/commit/d30c9ab81d060742412504a20f87fab8c1903908))
* **pattern:** support alternation syntax in command name position ([#91](https://github.com/fohte/runok/issues/91)) ([6fabb81](https://github.com/fohte/runok/commit/6fabb8188d26151ac06270d3f713f11e81899843))
* **pattern:** support multi-word alternation syntax in command position ([#94](https://github.com/fohte/runok/issues/94)) ([2fdea25](https://github.com/fohte/runok/commit/2fdea25efd93359b32b08228d6da1086d3c0ea9c))
* **pattern:** support wildcard `*` as command name in patterns ([#77](https://github.com/fohte/runok/issues/77)) ([82c343c](https://github.com/fohte/runok/commit/82c343c148ab0ea86f18fb41abcdd0f11f82ce8d))
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
* **sandbox:** implement macOS `SandboxExecutor` using Seatbelt/SBPL ([#67](https://github.com/fohte/runok/issues/67)) ([32d7e96](https://github.com/fohte/runok/commit/32d7e964757766b1abc10c5ce9fea3f1640355d6))
* **wrapper:** add `<opts>` and `<vars>` placeholders for wrapper patterns ([#84](https://github.com/fohte/runok/issues/84)) ([0d41c66](https://github.com/fohte/runok/commit/0d41c663217a6ce40cf64e3183dd15eeb0d7f07c))


### Bug Fixes

* **adapter:** evaluate extracted sub-command instead of raw input for simplified compound constructs ([#87](https://github.com/fohte/runok/issues/87)) ([0c463b7](https://github.com/fohte/runok/commit/0c463b7052401cadf55a3a557a7f570a4ea69e0c))
* **cli:** unwrap `Result` from `shell_quote_join` call in `route_check` ([#100](https://github.com/fohte/runok/issues/100)) ([730633e](https://github.com/fohte/runok/commit/730633e5f1270389357fea93c83ffc1de9406473))
* **command_parser:** skip `comment` nodes in `collect_commands` ([#88](https://github.com/fohte/runok/issues/88)) ([9882e01](https://github.com/fohte/runok/commit/9882e01bffdc221b71e735e8a1cb12025968cc32))
* **command_parser:** strip env-prefix variable assignments from command nodes ([#90](https://github.com/fohte/runok/issues/90)) ([c2f7c76](https://github.com/fohte/runok/commit/c2f7c76c7452e44ae4e1c85d95204ad55b41d291))
* **command_parser:** treat `variable_assignment` as transparent container to exclude bare assignments from command extraction ([#82](https://github.com/fohte/runok/issues/82)) ([ff881b5](https://github.com/fohte/runok/commit/ff881b5cc5c15b81879ffd1194474f3c87f301ef))
* **config:** preserve global `definitions.paths` during config merge ([#28](https://github.com/fohte/runok/issues/28)) ([7a30d16](https://github.com/fohte/runok/commit/7a30d16bfe8f02082daac7fc2c63530f78436a89))
* **hook:** include sandbox-wrapped `updatedInput` for `ask` decisions ([#81](https://github.com/fohte/runok/issues/81)) ([75bf7c4](https://github.com/fohte/runok/commit/75bf7c4c89580a8d99a572450a7c7ab60f8f33ed))
* **hook:** use `snake_case` serde rename for `HookInput` ([#76](https://github.com/fohte/runok/issues/76)) ([78f3e39](https://github.com/fohte/runok/commit/78f3e39aed345ade1a606f337ad3ed38b41fb29f))
* **linux-sandbox:** enforce glob patterns in deny list via bubblewrap ([#122](https://github.com/fohte/runok/issues/122)) ([dd02db7](https://github.com/fohte/runok/commit/dd02db71af9730e6c84247cce340da46d94423a6))
* **linux-sandbox:** remove obsolete `runok-linux-sandbox:` prefix from warning messages ([#128](https://github.com/fohte/runok/issues/128)) ([a3862e7](https://github.com/fohte/runok/commit/a3862e7b726c988ae473b9d72dedeb300c0595a1))
* **parser:** handle redirects in command rule matching ([#102](https://github.com/fohte/runok/issues/102)) ([10c9e9c](https://github.com/fohte/runok/commit/10c9e9cc98ff6bcd78e7eb1ffc0ffa5553a8896b))
* **pattern:** allow literal `[` as a command name in patterns ([#83](https://github.com/fohte/runok/issues/83)) ([ce99efe](https://github.com/fohte/runok/commit/ce99efed676f9499dde548cf153483793624bfe0))
* **pattern:** allow wildcard `*` in command position to match multi-word commands ([#98](https://github.com/fohte/runok/issues/98)) ([7d0b0ba](https://github.com/fohte/runok/commit/7d0b0ba87d62a5c2509120e0735794e575022eac))
* **pattern:** apply glob matching to literal tokens containing `*` ([#106](https://github.com/fohte/runok/issues/106)) ([b95f957](https://github.com/fohte/runok/commit/b95f957de7aeb90e2e30a0c00157a32af759a20b))
* **pattern:** match flags inside optional groups in order-independent manner ([#97](https://github.com/fohte/runok/issues/97)) ([6c029e6](https://github.com/fohte/runok/commit/6c029e6d657144b6fbecc3b7f78745c44cc02015))
* **pattern:** match non-aliased flags in order-independent manner ([#80](https://github.com/fohte/runok/issues/80)) ([ebb23e3](https://github.com/fohte/runok/commit/ebb23e3d87a3fd2a4bdccfa26a83a75847408f84))
* **pattern:** prevent flags from consuming literal `]` as a value in bracket commands ([#85](https://github.com/fohte/runok/issues/85)) ([68daac1](https://github.com/fohte/runok/commit/68daac17edf0f7a22f03f3fc5cec756e098b0365))
* **pattern:** prevent wildcard from matching across shell operators in compound commands ([#108](https://github.com/fohte/runok/issues/108)) ([067ab7e](https://github.com/fohte/runok/commit/067ab7ec971f0281f10a7eccb9e64523215eb295))
* **pattern:** treat `*` inside alternation parts as a glob wildcard ([#101](https://github.com/fohte/runok/issues/101)) ([0ab984f](https://github.com/fohte/runok/commit/0ab984fd299077248cdb7caab5898f33e536baca))
* resolve ETXTBSY flaky tests on Linux CI by retrying spawn ([#32](https://github.com/fohte/runok/issues/32)) ([6980503](https://github.com/fohte/runok/commit/698050368454439dd61e8cb1cb5248d84c11c0f0))
* **rule_engine:** resolve unmatched sub-commands in compound evaluation via `defaults.action` ([#79](https://github.com/fohte/runok/issues/79)) ([43ba553](https://github.com/fohte/runok/commit/43ba5533a31a0b32bac119290b64b1c938dbfe1f))
* **sandbox:** fall back to `defaults.sandbox` when matched rule has no sandbox attribute ([#78](https://github.com/fohte/runok/issues/78)) ([eb53670](https://github.com/fohte/runok/commit/eb536704138b1e3e88eef69d957bb9843c372e7b))


### Dependencies

* update rust crate anyhow to v1.0.102 ([#117](https://github.com/fohte/runok/issues/117)) ([ba79bd5](https://github.com/fohte/runok/commit/ba79bd521d598d01155af16c367406e7f3260ecc))
* update rust crate clap to v4.5.58 ([#47](https://github.com/fohte/runok/issues/47)) ([fca519c](https://github.com/fohte/runok/commit/fca519c4fb41a43eea71161fd851d34d20248232))
* update rust crate clap to v4.5.59 ([#86](https://github.com/fohte/runok/issues/86)) ([cc80443](https://github.com/fohte/runok/commit/cc80443567516a43a3858ae1b03508b66c03a11f))
* update rust crate clap to v4.5.60 ([#113](https://github.com/fohte/runok/issues/113)) ([34219e0](https://github.com/fohte/runok/commit/34219e0fa452ec94b4398cdc65d4c0e3495b7840))
* update rust crate landlock to v0.4.4 ([#69](https://github.com/fohte/runok/issues/69)) ([9abbb8d](https://github.com/fohte/runok/commit/9abbb8d940cbc03906995de918059fffca773f6d))
* update rust crate serde_json to v1.0.149 ([#20](https://github.com/fohte/runok/issues/20)) ([98d5d1a](https://github.com/fohte/runok/commit/98d5d1a646a7ebe6cb154fe2bd58ca322a21c294))
* update rust crate serde-saphyr to v0.0.17 ([#14](https://github.com/fohte/runok/issues/14)) ([336b13d](https://github.com/fohte/runok/commit/336b13d0aec0a3f84999bde1aa4d86939b70470b))
* update rust crate serde-saphyr to v0.0.18 ([#42](https://github.com/fohte/runok/issues/42)) ([ea3bad4](https://github.com/fohte/runok/commit/ea3bad46cdfdff43e65af69cc201abdfabf0ec28))
* update rust crate serde-saphyr to v0.0.19 ([#70](https://github.com/fohte/runok/issues/70)) ([aa6e315](https://github.com/fohte/runok/commit/aa6e315b300f34a9ab156d993ca2c3551d07da21))
* update rust crate serde-saphyr to v0.0.20 ([#130](https://github.com/fohte/runok/issues/130)) ([0f502c2](https://github.com/fohte/runok/commit/0f502c2bd766f50d0e32127ef3830a5bc688f6d2))
* update rust crate sha2 to v0.10.9 ([#46](https://github.com/fohte/runok/issues/46)) ([62c8316](https://github.com/fohte/runok/commit/62c8316d957b05f7a9ecd1f74ca864c21b58fb07))
