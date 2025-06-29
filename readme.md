#### malsmug

Before building we have to set the nightly builder in order to be able to use `oxc`
```bash
rustup override set nightly --path .
```

Build everything:
```bash
cargo build
```

Run:
```bash
# debug and verbose information
# execute script on www.facebook.com
./target/debug/malsmug -v -d --file-path js-samples/file1.js all --url-to-visit https://www.facebook.com

# not debug and not verbose
# run script on a login form example
./target/debug/malsmug --file-path js-samples/file1.js all --url-to-visit https://www.facebook.com
```

Usage:
```bash

Usage: malsmug [OPTIONS] --file-path <FILE_PATH> <COMMAND>

Commands:
  all # run both sast and dast
  sast
  dast
  help  Print this message or the help of the given subcommand(s)

Options:
      --file-path <FILE_PATH>
  -v, --verbose
  -d, --debug
  -h, --help                   Print help
```

#### static analysis ioc(s)

- expression including eval (ast)
- expression including execScript (ast)
- call of `document.write` with potential html elements as arguments (regex or ast)

Some identifiers from `oxc` Abstract Syntax Tree:
- StaticMemberExpression function calls: `CallExpression -> callee:StaticMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]`
- ComputedMemberExpression function calls:  `CallExpression -> callee:ComputedMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]`

#### dynamic analysis ioc(s)

- call of `cookie.get`
- call of `cookie.set`
- call of `localStorage.getItems`
- call of `localStorage.setItems`
- call of `document.write`
- call of `window.eval`
- call of `window.execScript`
- call of `document.addEventListener`
- creation of new html elements that can trigger network calls
- low domain reputation score
- suspicious form input data sent with HTTP request

#### todo
- rename `file_analysis_report.has_been_analysed`
- use only `file_analysis_report` and not `file_analysis` or `file_report` in FileAnalysisReport variables

#### Usage example
```
curl --location 'http://127.0.0.1:11234/analyse-file' \
--form 'file_for_analysis=@"/home/dimeko/dev/mal-js-detection/js-samples/file2.js"' \
--form 'bait_websites="https://facebook.com,https://google.com,https://cnn.com"' \
--form 'static_analysis="true"' \
--form 'dynamic_analysis="true"'
```