KERNEL_ROOT_DIR=$1
BZIMAGE="$(find $KERNEL_ROOT_DIR -type f -name bzImage)"
/snapchange/QEMU/build/qemu-system-x86_64 \
	-m 4G \
	-smp 1 \
	-kernel "$BZIMAGE" \
	-append "console=ttyS0 root=/dev/ram earlyprintk=serial" \
    -initrd /snapchange/qemu_stuff/initramfs.cpio.gz \
	-nographic \
    -enable-kvm \
    -cpu kvm64 \
	-pidfile vm.pid \
	2>&1 | tee vm.log
	#-drive file=/snapchange/qemu_stuff/IMAGE/bookworm.img \
	#-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	#-net nic,model=e1000 \
