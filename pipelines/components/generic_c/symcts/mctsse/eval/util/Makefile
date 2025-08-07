libshm.so: libshm.o libshm.h
	gcc $^ -shared -o $@

libshm.o: libshm.c
	gcc -c -g -O3 -fPIC $< -o $@ -lrt