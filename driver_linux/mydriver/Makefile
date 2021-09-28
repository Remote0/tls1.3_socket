obj-m+=mychar.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
	$(CC) test_mychar.c -o test_mychar

test:
	$(CC) test_mychar.c -o test_mychar
	
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
	rm test_mychar
