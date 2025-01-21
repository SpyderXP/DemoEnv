.PHONY: all demo_logger demo_crypto demo_main clean

all: 
	$(MAKE) -C demo_logger
	$(MAKE) -C demo_crypto
	$(MAKE) -C demo_main

demo_logger: 
	$(MAKE) -C demo_logger

demo_crypto: 
	$(MAKE) -C demo_crypto

demo_main: 
	$(MAKE) -C demo_main

clean:
	$(MAKE) -C demo_logger clean
	$(MAKE) -C demo_crypto clean
	$(MAKE) -C demo_main clean