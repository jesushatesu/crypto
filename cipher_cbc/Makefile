obj-m += jes_crypto_cbc.o

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	sudo insmod jes_crypto_cbc.ko
	sudo dmesg -c

upload:
	sudo rmmod jes_crypto_cbc.ko
	sudo dmesg -c
