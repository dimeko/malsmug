#### mal-js-detector

Before building we have to set the nightly builder in order to be able to use `ocx`
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
./target/debug/malsmug -v -d --file-path js-samples/file_test.js all --url-to-visit https://www.facebook.com

# not debug and not verbose
# run script on a login form example
./target/debug/malsmug --file-path js-samples/file_test.js all --url-to-visit https://www.login_example.com
```

#### static analysis ioc(s)

- eval (ast)
- execScript (ast)
- http://urls (regex)
- `<script></script>` in string (regex or ast)

todo:
- document.write and element is script/link/iframe/object/embed or img/audio/video/source/track
- withCredentials directive in xhr

Identifiers from `ocx` Abstract Syntax Tree:
- StaticMemberExpression function calls: CallExpression -> callee:StaticMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]
- ComputedMemberExpression function calls:  CallExpression -> callee:ComputedMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]

#### dynamic analysis ioc(s)
All ioc(s) are detected using hooks:

- request on black listed ip
- cookie.get
- cookie.set
- localStorage.getItems
- localStorage.setItems
- creation of new html elements that can trigger network calls
- form input data sent with HTTP request
- call to `document.eval` and `document.execScript`

#### todo
- add more keys to known KNOWN_SENSITIVE_DATA_KEYS (eg ASP.NET cookie)
- explore how hooks to event listeners could be used (for now all `addEventListener` calls are hooked)
- hook window.sessionStorage