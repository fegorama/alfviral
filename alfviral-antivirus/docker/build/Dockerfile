FROM alpine:latest

ARG VERSION=0.5.5
ARG PLUGINS_VERSION=0.5.3

RUN apk update

RUN cd $HOME && \
    apk add --no-cache clamav clamav-libunrar gcc musl-dev zlib-dev file bzip2-dev git bc sed autoconf automake libtool tree make && \
    git clone https://github.com/google/brotli.git && \
    cd brotli && ./bootstrap && ./configure && make && make install && cd $HOME && rm -r brotli && \
    wget -O c-icap.tar.gz https://sourceforge.net/projects/c-icap/files/c-icap/0.5.x/c_icap-$VERSION.tar.gz/download && \
    tar zxfv c-icap.tar.gz && \
    cd c_icap-$VERSION && ./configure --prefix=/usr/local/c-icap && make && make install && cd $HOME && rm -r c_icap-$VERSION c-icap.tar.gz && \
    wget -O c-icap-plugins.tar.gz https://sourceforge.net/projects/c-icap/files/c-icap-modules/0.5.x/c_icap_modules-$PLUGINS_VERSION.tar.gz/download && \
    tar zxfv c-icap-plugins.tar.gz && \
    cd c_icap_modules-$PLUGINS_VERSION && ./configure --with-c-icap=/usr/local/c-icap --prefix=/usr/local/c-icap && make && make install && \
    cd $HOME && rm -r c_icap_modules-$PLUGINS_VERSION c-icap-plugins.tar.gz && \
    libtool --finish /usr/local/c-icap/lib/c_icap/ && \
    apk del gcc musl-dev git autoconf automake make tree sed bc

# Install ssh
# TODO merge RUNs
RUN apk add bash git openssh rsync augeas shadow rssh
RUN deluser $(getent passwd 33 | cut -d: -f1) && \
    delgroup $(getent group 33 | cut -d: -f1) 2>/dev/null || true && \
    mkdir -p ~root/.ssh /etc/authorized_keys && chmod 700 ~root/.ssh/ && \
    augtool 'set /files/etc/ssh/sshd_config/AuthorizedKeysFile ".ssh/authorized_keys /etc/authorized_keys/%u"' && \
    echo -e "Port 22\n" >> /etc/ssh/sshd_config && \
    cp -a /etc/ssh /etc/ssh.cache && \
    rm -rf /var/cache/apk/*

COPY clamd.conf /etc/clamav/
COPY freshclam.conf /etc/clamav/
COPY c-icap.conf /usr/local/c-icap/etc/
COPY virus_scan.conf /usr/local/c-icap/etc/
COPY clamd_mod.conf /usr/local/c-icap/etc/

COPY entry.sh /usr/bin/
# COPY clamav_start.sh /usr/bin/
# COPY sshd_start.sh /usr/bin/

RUN chmod +x /usr/bin/entry.sh
# RUN chmod +x /usr/bin/clamav_start.sh
# RUN chmod +x /usr/bin/sshd_start.sh

RUN mkdir /run/clamav
RUN chmod 0770 /run/clamav
RUN chown -R clamav:clamav /run/clamav

# For Alfresco
#RUN mkdir -p /usr/local/tomcat/alf_data

# Expose ports for ICAP and STREAM
EXPOSE 1344
EXPOSE 3310
EXPOSE 22

ENTRYPOINT ["entry.sh"]

HEALTHCHECK CMD /usr/local/c-icap/bin/c-icap-client < /dev/null || exit 1

CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"]
