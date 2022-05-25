SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

clean:
	cd ecdh_aes_cbc_256/; make clean
	cd ecdh_aes_ecb_256/; make clean
	cd mqtt/; make clean

.PHONY: all $(SUBDIRS)
