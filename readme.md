#### mal-js-detector

Build puppeteer image:
```bash
docker  build . -t js-dast -f docker/js_dast_Dockerfile
```

Run docker:
```bash
docker run --rm --network=none -v $(pwd)/js-samples/file4.js:/js_dast/samples/file.js --cap-add=NET_ADMIN js-dast /js_dast/samples/file.js
```

#### static analysis ioc

- eval (ast)
- execScript (ast)
- http://urls (regex)
- `<script></script>` in string (regex or ast)
- document.write and element is script/link/iframe/object/embed or img/audio/video/source/track
- withCredentials directiv ein xhr

Identifiers:
- StaticMemberExpression function calls: CallExpression -> callee:StaticMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]
- ComputedMemberExpression function calls:  CallExpression -> callee:ComputedMemberExpression -> object: Identifier . property: IdentifierName -> arguments: Vec[BinaryExpression (rec)]


#### dynamic analysis ioc

- request on black listed ip
- cookie.get
- call to localStorage

#### todo
- analyze known cookie access (eg ASP.NET cookie)
- research more on `getEventListeners` and how it could be used
- hook known window property access (e.g. window.sessionStorage)
- add free domain reputation resolver (`curl 'https://www.spamhaus.org/api/v1/sia-proxy/api/intel/v2/byobject/domain/cnn.com/overview' --compressed -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0'`)