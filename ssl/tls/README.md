# TLS

## 结构

|        文件 | 说明                               |
| ----------: | :--------------------------------- |
|  client.cpp | 客户端代码                         |
| gencert.cpp | 用于生成服务器端证书和公私钥的代码 |
|  server.cpp | 服务端代码                         |

> 通信的密码套件在服务端被强制设定为`ECDHE_SM4_SM3`(参见[server.cpp:62](https://github.com/sammyne/mastering-gmssl/blob/0271e79589b1f3ba706152d0294904fd02a22faa/ssl/tls13/server.cpp#L62))

## 运行流程

假设编译 client.cpp、gencert.cpp 和 server.cpp 生成的可执行文件分别为 client、gencert 和 server

### 1. 生成证书

```sh
./gencert
```

### 2. 运行服务器

```sh
// 需要管理员权限
sudo ./server
```

### 3. 运行客户端

```sh
./client
```
