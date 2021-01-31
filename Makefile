# Makefile for src/mod/idea.mod/

srcdir = .


doofus:
	@echo ""
	@echo "Let's try this from the right directory..."
	@echo ""
	@cd ../../../ && make

static: ../idea.o

modules: ../../../idea.$(MOD_EXT)

../idea.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) -DMAKING_MODS -c $(srcdir)/idea.c
	@rm -f ../idea.o
	mv idea.o ../

../../../idea.$(MOD_EXT): ../idea.o
	$(LD) -o ../../../idea.$(MOD_EXT) ../idea.o $(XLIBS)
	$(STRIP) ../../../idea.$(MOD_EXT)

depend:
	$(CC) $(CFLAGS) $(CPPFLAGS) -MM $(srcdir)/idea.c > .depend

clean:
	@rm -f .depend *.o *.$(MOD_EXT) *~
distclean: clean

#safety hash
../idea.o: .././idea.mod/idea.c ../../../src/mod/module.h \
 ../../../src/main.h ../../../config.h ../../../src/lang.h \
 ../../../src/eggdrop.h ../../../src/flags.h ../../../src/proto.h \
 ../../../lush.h ../../../src/misc_file.h ../../../src/cmdt.h \
 ../../../src/tclegg.h ../../../src/tclhash.h ../../../src/chan.h \
 ../../../src/users.h ../../../src/compat/compat.h \
 ../../../src/compat/inet_aton.h ../../../src/compat/snprintf.h \
 ../../../src/compat/memset.h ../../../src/compat/memcpy.h \
 ../../../src/compat/strcasecmp.h ../../../src/compat/strftime.h \
 ../../../src/mod/modvals.h ../../../src/tandem.h \
 ../idea.mod/idea.h ../idea.mod/usuals.h
