FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install -y \
    build-essential \
    git \
    libssl-dev \
    lcov \
    ruby \
    wget

# get an appropriate version of cmake
RUN wget -qO- "https://cmake.org/files/v3.18/cmake-3.18.1-Linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C /usr/local

# set up certs for testing
RUN openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout ca.key -out ca.crt -subj "/C=US"
RUN openssl req -nodes -sha256 -subj "/C=US/ST=WA/L=Seattle/O=AWS/CN=CSDK Docker" -new -keyout server.key -out server.csr
RUN openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

COPY . /csdk

RUN cmake \
    -S csdk/ \
    -B build/ \
    -DBUILD_TESTS=1 \
    -G "Unix Makefiles" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS=' \
        --coverage \
        -DLIBRARY_LOG_LEVEL=LOG_DEBUG \
        -DBROKER_ENDPOINT=\"localhost\" \
        -DROOT_CA_CERT_PATH=\"/ca.crt\" \
        -DSERVER_ROOT_CA_CERT_PATH=\"/ca.crt\" \
        '\
    -DDOWNLOAD_CERTS=0 \
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
    -DAWS_IOT_ENDPOINT="aws-iot-endpoint" \
    -DROOT_CA_CERT_PATH="root-ca-path" \
    -DCLIENT_CERT_PATH="certificate-path" \
    -DCLIENT_PRIVATE_KEY_PATH="private-key-path"
