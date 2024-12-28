## Setup
```bash
git clone https://github.com/threatofwar/go-login-restapi.git
```
```bash
cd go-login-restapi/
```
```bash
go mod init go-login-restapi
```
```bash
go mod tidy
```
```bash
go run main.go
```

## Testing
### Login
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "123"}'
```
### Accessing profile with access token
```bash
curl -X GET http://localhost:8080/auth/profile -H "Authorization: Bearer <access_token>"
```
### Refresh token
```bash
curl -X POST http://localhost:8080/refresh-token -H "Content-Type: application/json" -d '{"refresh_token": "<refresh_token>"}'
```
### Accessing profile with new access token
```bash
curl -X GET http://localhost:8080/auth/profile -H "Authorization: Bearer <access_token>"
```
