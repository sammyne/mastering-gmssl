FROM fedora:29

RUN curl -o /etc/yum.repos.d/fedora.repo http://mirrors.aliyun.com/repo/fedora.repo &&\
  curl -o /etc/yum.repos.d/fedora-updates.repo http://mirrors.aliyun.com/repo/fedora-updates.repo &&\
  dnf makecache &&\
  dnf install gcc-c++ -y &&\
  dnf install make -y &&\
  dnf install cmake -y &&\
  dnf install git -y &&\
  mkdir /cpp
RUN cd /cpp &&\
  git clone https://github.com/openssl/openssl.git
RUN cd /cpp/openssl && git checkout OpenSSL_1_1_1b && ./config --prefix=/usr/local/ssl && make && make install 