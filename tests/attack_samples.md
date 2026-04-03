# Attack Samples for SentinelShield

##Normal Traffic
curl "http://127.0.0.1:5000/"
curl "http://127.0.0.1:5000/?q=hello"

## SQL Injection
1. `/?id=1' OR '1'='1`
2. `/?q=union select user, password from users`
3. `/?id=1; DROP TABLE users`

## Cross-Site Scripting (XSS)
1. `/?q=<script>alert('XSS')</script>`
2. `/?name=<img src=x onerror=alert(1)>`

## Directory Traversal / LFI    //
1. `/?file=../../etc/passwd`
2. `/?page=../../../windows/win.ini`

## Command Injection
1. `/?cmd=cat /etc/passwd`
2. `/?ip=127.0.0.1; ls -la`

## Rate Limiting Test
Run this in bash to trigger rate limiting:
```bash
for i in {1..200}; do curl -s "http://localhost:5000/" > /dev/null; done
```
