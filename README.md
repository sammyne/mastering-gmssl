# GmSSL

## Examples

- [生成 CSR](crypto/x509/csr.cpp)

## 项目结构

- 示例代码主要分布在`crypto`和`ssl`两个文件夹
  - 文件的层级结构和[`GmSSL`](https://github.com/guanzhi/GmSSL)的保持一致。例如，`sm2`的示例在`crypto/sm2`文件夹，原始的`sm2`源码也在对应的文件夹
- `docker`文件夹是构建 GmSSL 开发环境的`Dockerfile`
  - `gmssl`库安装在`/usr/local/gmssl`目录
- `develop.sh`启动一个基于`docker/Dockerfile`(脚本中假设创建的镜像名为`gmssl:v1`)，并把当前目录挂载到容器里面的`/cpp`目录
- 项目的编译依赖于版本`>=3.12`的`cmake`
