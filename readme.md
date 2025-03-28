#### mal-js-detector

Build puppeteer image:
```bash
docker  build . -t js-dast -f docker/js_dast_Dockerfile
```

Run docker:
```bash
docker run --rm --network=none -v $(pwd)/js-samples/file4.js:/js_dast/samples/file.js --cap-add=NET_ADMIN js-dast /js_dast/samples/file.js
```