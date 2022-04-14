Giới thiệu: app mã hoá và giải mã chuỗi sử dụng aes-128\
Công nghệ sử dụng: HTML, CSS, JS, Webassembly\
Các bước build từ go sang wasm:\

- set GOOS=js\
- set GOARCH=wasm\
- go build -o main.wasm main.go\
  Để chạy có thể sử dụng live server
