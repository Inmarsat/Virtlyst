FROM lmc_build_env as builder

FROM alpine:3.11.3

RUN echo 'http://dl-cdn.alpinelinux.org/alpine/edge/testing' >> /etc/apk/repositories

RUN apk update && apk add \
  qt5-qtbase \
  qt5-qtbase-sqlite \
  libssh \
  grantlee \
  openssh-client \
  libvirt-libs 

RUN apk add qt5-qtbase-postgresql qt5-qtdeclarative virt-install py3-libvirt py3-libxml2

# Copy over cutelyst installation
COPY --from=builder /usr/local /usr/local

WORKDIR /usr/local/Virtlyst

RUN echo "/lib" >> /etc/ld-musl-x86_64.path
RUN echo "/usr/lib" >> /etc/ld-musl-x86_64.path
RUN echo "/usr/local/lib" >> /etc/ld-musl-x86_64.path
RUN echo "/usr/local/lib64" >> /etc/ld-musl-x86_64.path

RUN mkdir /usr/local/Virtlyst/data /usr/local/Virtlyst/root
COPY Virtlyst/build/src/libVirtlyst.so /usr/local/Virtlyst/
COPY Virtlyst/root /usr/local/Virtlyst/root/

RUN ldconfig || /bin/true

EXPOSE 3000
VOLUME /usr/local/Virtlyst/data
CMD ["/usr/local/bin/cutelyst-wsgi2","--ini","config.ini"]
