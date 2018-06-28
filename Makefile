include config.mk


clib := lem/sodiumb/core.so

all: $(clib)

.PHONY: test strip

$(clib): lem/sodiumb/core.c
	$(CC) $(CFLAGS) $(LDFLAGS) \
	lem/sodiumb/core.c \
	 -o $@ 

strip: $(clib)
	strip -s $(clib)

install: $(clib) strip
	mkdir -p $(cmoddir)/lem/sodiumb
	mkdir -p $(lmoddir)/lem/sodiumb
	install -m 755 lem/sodiumb/core.so     $(cmoddir)/lem/sodiumb/

clean:
	rm -f lem/sodiumb/core.so
