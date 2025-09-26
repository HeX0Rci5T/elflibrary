obj	= utils.o elf.o
BDIR	= ./build
CFLAGS	= -w
PWD	= $(shell pwd)

all: library

install: library
	sudo cp -r $(PWD) /usr/local/include/
	sudo cp $(PWD)/$(BDIR)/libelflib.a /usr/local/lib/
	sudo ldconfig

test:
	g++ main.cc -lx86disass -lelflib -o ./main
	./main

.PHONY: library
library: $(obj)
	cd $(BDIR); ar rvs libelflib.a $^

%.o: src/utils/%.c
	gcc -c $< -o $(BDIR)/$@ $(CFLAGS)

%.o: src/elf/%.cc
	g++ -c $< -o $(BDIR)/$@ $(CFLAGS)
