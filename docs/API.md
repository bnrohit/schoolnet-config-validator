# API Reference

Base URL: `http://localhost:8000`

Interactive docs: `http://localhost:8000/docs`

## Health

```bash
curl http://localhost:8000/api/v1/health
```

## Vendors

```bash
curl http://localhost:8000/api/v1/vendors
```

## Rule catalog

```bash
curl http://localhost:8000/api/v1/rules
```

## Demo configs

```bash
curl http://localhost:8000/api/v1/examples
```

## Sanitize config

```bash
curl -X POST http://localhost:8000/api/v1/sanitize \
  -H "Content-Type: application/json" \
  -d '{"vendor":"cisco_ios","config_text":"enable secret mysecret"}'
```

## Validate pasted config

```bash
curl -X POST http://localhost:8000/api/v1/validate \
  -H "Content-Type: application/json" \
  -d @examples/validate-request.sample.json
```

## Validate uploaded file

```bash
curl -F "file=@configs/example-broken-switch.txt" \
  -F "vendor=cisco_ios" \
  http://localhost:8000/api/v1/validate/upload
```

## Batch validate

```bash
curl -X POST http://localhost:8000/api/v1/validate/batch \
  -H "Content-Type: application/json" \
  -d @examples/batch-request.sample.json
```

## Markdown report

Send a validation result back to the report endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/report/markdown \
  -H "Content-Type: application/json" \
  -d '{"result":{"hostname":"demo","summary":{"total":0}}}'
```

## Remediation script

```bash
curl -X POST http://localhost:8000/api/v1/remediate \
  -H "Content-Type: application/json" \
  -d '{"vendor":"cisco_ios","findings":[]}'
```
