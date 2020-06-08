CFLAGS += -g

medea: medea.c
	$(CC) $< $(CFLAGS) -Wl,-lzstd -o $@

run: medea
	./medea

clean:
	rm -f medea
