obj-m+=kietchar.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) testsoft.c -o testsoft
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm testsoft
