# GmSSL

## 必备条件

以下假设在本地 Linux 开发(不借助`docker/Dockerfile`描述的镜像)

|    软件 | 最低版本 |
| ------: | :------- |
|   cmake | 3.12.1   |
| gcc-c++ | 8.2.1    |
|     git | 2.19.1   |
|    make | 4.2.1    |

## 编译安装

```sh
// 下载项目到本地
git clone https://github.com/sammyne/mastering-gmssl.git
// 进入项目文件夹
cd mastering-gmssl

// 创建额外的build目录用于放置编译的中间输出，
mkdir build
// 进入build目录
cd build

// 调用cmake生成Makefile
cmake ..
// 编译生成各个示例的可执行文件
make
```

## `crypto`示例代码

- [SM2 签名和验签](crypto/sm2/sm2.cpp)
- [生成 CSR](crypto/x509/csr.cpp)

## `ssl`示例代码

- [基于国密套件的 SSL 通信](ssl/tls)

## 项目结构

- 示例代码主要分布在`crypto`和`ssl`两个文件夹
  - 文件的层级结构和[`GmSSL`](https://github.com/guanzhi/GmSSL)的保持一致。例如，`sm2`的示例在`crypto/sm2`文件夹，原始的`sm2`源码也在对应的文件夹
- `docker`文件夹是构建 GmSSL 开发环境的`Dockerfile`
  - `gmssl`库安装在`/usr/local/gmssl`目录
- `develop.sh`启动一个基于`docker/Dockerfile`(脚本中假设创建的镜像名为`gmssl:v1`)，并把当前目录挂载到容器里面的`/cpp`目录
- 项目的编译依赖于版本`>=3.12`的`cmake`
