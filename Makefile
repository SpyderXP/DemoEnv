.PHONY: all demo_common demo_logger demo_crypto demo_lib demo_main clean

all: 
	$(MAKE) -C demo_common LIB_TYPE=$(LIB_TYPE)
	$(MAKE) -C demo_logger LIB_TYPE=$(LIB_TYPE)
	$(MAKE) -C demo_crypto LIB_TYPE=$(LIB_TYPE)
	$(MAKE) -C demo_main LIB_TYPE=$(LIB_TYPE)

demo_lib: 
	$(MAKE) -C demo_common LIB_TYPE=$(LIB_TYPE)
	$(MAKE) -C demo_logger LIB_TYPE=$(LIB_TYPE)
	$(MAKE) -C demo_crypto LIB_TYPE=$(LIB_TYPE)

demo_common: 
	$(MAKE) -C demo_common LIB_TYPE=$(LIB_TYPE)

demo_logger: 
	$(MAKE) -C demo_logger LIB_TYPE=$(LIB_TYPE)

demo_crypto: 
	$(MAKE) -C demo_crypto LIB_TYPE=$(LIB_TYPE)

demo_main: 
	$(MAKE) -C demo_main LIB_TYPE=$(LIB_TYPE)

clean:
	$(MAKE) -C demo_common clean
	$(MAKE) -C demo_logger clean
	$(MAKE) -C demo_crypto clean
	$(MAKE) -C demo_main clean