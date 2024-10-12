#!/bin/bash
#

pushd `pwd`
cd $(dirname $0)

exec qemu-system-x86_64 -enable-kvm -machine q35 \
    -smp cpus=4 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
    -drive format=raw,file=fat:rw:esp -cpu max \
    -m size=16G -display gtk,zoom-to-fit=off,gl=on \
    -usb \
    -device virtio-gpu-gl,hostmem=1G \
    -device qemu-xhci,id=xhci \
    -device usb-mouse,bus=xhci.0 -device usb-kbd,bus=xhci.0

popd
