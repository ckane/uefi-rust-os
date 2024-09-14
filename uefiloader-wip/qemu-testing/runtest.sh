#!/bin/bash
#

pushd `pwd`
cd $(dirname $0)

exec qemu-system-x86_64 -enable-kvm -machine q35 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
    -drive format=raw,file=fat:rw:esp -cpu max \
    -usb \
    -device usb-ehci,id=ehci \
    -device usb-mouse,bus=ehci.0 -device usb-kbd,bus=ehci.0 \
    -vga virtio -m size=12G -machine q35 -display gtk,zoom-to-fit=off,gl=on

popd
