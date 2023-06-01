FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang cmake

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install
RUN make -j8
RUN make install

RUN clang /repo/mayhem/fuzz_isprefix.cpp -fsanitize=fuzzer,address -I /repo/src/ /repo/src/isprefix.c -I /repo/build/src/ -o /fuzz

FROM ubuntu:22.04 as package

COPY --from=builder /fuzz /fuzz_isprefix
