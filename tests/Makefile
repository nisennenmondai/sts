TEST1=ecdh_aes_ecp_256
TEST1_DIR=./ecdh_aes_ecp_256/

all:
	@if [ -f "$(TEST1_DIR)$(TEST1)" ]; then\
		echo "tests: Built Target '$(TEST1)'";\
		else \
		cd $(TEST1);\
		make;\
		fi

clean:
	@if [ -f "$(TEST1_DIR)$(TEST1)" ]; then\
		cd $(TEST1); rm $(TEST1); echo "tests: Clean Target '$(TEST1)'";\
		else \
		echo "tests: Nothing to clean '$(TEST1)'";\
		fi
