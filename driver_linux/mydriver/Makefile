obj-m+=mychar.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules -I.
	$(CC) test_mychar.c -o test_mychar -I.

test:
	$(CC) test_mychar.c -o test_mychar -I.

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test_mychar
