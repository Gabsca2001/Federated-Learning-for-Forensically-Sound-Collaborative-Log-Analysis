#!/bin/sh
set -eu

mkdir -p /var/lib/swtpm /run/swtpm
chmod 0777 /run/swtpm
chmod 0777 /var/lib/swtpm

rm -f \
  /run/swtpm/swtpm.sock \
  /run/swtpm/swtpm.sock.ctrl \
  /run/swtpm/swtpm.ctrl

exec swtpm socket \
  --tpm2 \
  --tpmstate dir=/var/lib/swtpm \
  --server type=unixio,path=/run/swtpm/swtpm.sock,mode=0666 \
  --ctrl type=unixio,path=/run/swtpm/swtpm.sock.ctrl,mode=0666 \
  --flags not-need-init,startup-clear \
  --log level=2
  