#!/usr/bin/env bash

set -e

if [ -e /run/clamav/clamd.sock ]; then
	rm /run/clamav/clamd.sock
fi

if [ ! -e /var/lib/clamav/main.cvd ]; then
	freshclam
fi

freshclam -d -c 6 &
clamd &

while [ ! -e /run/clamav/clamd.sock ]; do
	sleep 5
done

/usr/local/c-icap/bin/c-icap -N -D &

pids=`jobs -p`
exitcode=0

ssh-keygen -A

if [ -w ~/.ssh ]; then
    chown root:root ~/.ssh && chmod 700 ~/.ssh/
fi
if [ -w ~/.ssh/authorized_keys ]; then
    chown root:root ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi
if [ -w /etc/authorized_keys ]; then
    chown root:root /etc/authorized_keys
    chmod 755 /etc/authorized_keys
    # test for writability before attempting chmod
    for f in $(find /etc/authorized_keys/ -type f -maxdepth 1); do
        [ -w "${f}" ] && chmod 644 "${f}"
    done
fi

getent group alfresco >/dev/null 2>&1 || groupadd -g 1000 alfresco
getent passwd alfresco >/dev/null 2>&1 || useradd -r -m -p '$5$aL/PMDGuA7iKXras$p3CySbDFUoOmkTGXWxtKP5VL9o9irFXTa94jAeenDIB' -u 1000 -g 1000 -s /bin/bash -c 'Alfresco User' alfresco

echo 'set /files/etc/ssh/sshd_config/PasswordAuthentication yes' | augtool -s 1> /dev/null

trap stop SIGINT SIGTERM
$@ &
#pid="$!"
#mkdir -p /var/run/$DAEMON && echo "${pid}" > /var/run/$DAEMON/$DAEMON.pid

terminate() {
    for pid in $pids; do
        if ! kill -0 $pid 2>/dev/null; then
            wait $pid
            exitcode=$?
        fi
    done
    kill $pids 2>/dev/null
}

wait
exit $?
