FROM ubuntu:xenial

RUN apt-get update && apt-get install -y \
    libssl-dev=1.0.2g-'*'\
    libtool=2.4.6-'*' \
    automake=1:1.15-'*' \
    autoconf=2.69-'*' \
    make=4.1-'*' \
    curl=7.47.'*' \
    flex=2.6.0-'*' \
    bison=2:3.0.4.'*' \
    libaudit-dev=1:2.'*' \
    libauparse-dev=1:2.'*' \
    libev-dev=1:4.22-'*' \
    libglib2.0-dev=2.48.2-'*'

# Copy glib config header.
RUN cp /usr/lib/x86_64-linux-gnu/glib-2.0/include/glibconfig.h /usr/include/glib-2.0/

# Prepare libpcap
WORKDIR /tmp/libpcap
RUN curl http://www.tcpdump.org/release/libpcap-1.9.1.tar.gz | tar -xz --strip-components 1
RUN ./configure
RUN make && make install


# Prepare libdssl.
COPY OpenSource /tmp/OpenSource
WORKDIR /tmp/OpenSource/pcapreplay/libdssl
RUN cd build && libtoolize
RUN autoreconf -i
RUN automake --add-missing
RUN ./configure
RUN make
RUN make install

WORKDIR /
