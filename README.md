# FastAPI Casbin Authorization

Small proof of concept for FastAPI + Cabin Redis Watcher.

The objectives for this poc:

- Learn how to use casbin redis watcher to authorize FastAPI endpoints
- Verify that the casbin watcher behaves the way I expect
- Verify that redis>=5 works with my PRs

## Usage

Start redis (or valkey in this example):

```bash
docker run --rm -d -p 6379:6379 --name authz ghcr.io/valkey-io/valkey:latest
```

Start one (or more) instances of the application:

```bash
uv run fastapi dev main.py --port 8000
```

## Manual testing

Load `alice, data1, get` permission:

```bash
curl -X 'POST' \
  'http://localhost:8001/permission/add?sub=alice&obj=data1&act=get' \
  -H 'accept: application/json' \
  -d ''
```

Test the protected endpoint using a dummy jwt:

```bash
curl -X 'GET' \
  'http://localhost:8001/protected?obj=data1' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.0f1spqZjFKUCm5N5Tkkyeyw-cc5ympEn-O--YbaR6b0'
```