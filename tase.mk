TASE_PLUGIN_PATH=$(abspath $(dir $(CC))../lib/LLVMTase.so)
OPT=$(dir $(CC))opt
LLC=$(dir $(CC))llc
DISAS=$(dir $(CC))llvm-dis
OBJDUMP=objdump -d -w -M suffix -j .text

TASE_CORE=$(abspath $(TOP))/core_instrumented
TASE_MODELED=$(abspath $(TOP))/core_modeled
TASE_MODELED_FLAGS=-tase-modeled-functions $(TASE_MODELED)
PROJECT_TASE_ALL=$(abspath $(TOP))/openssl.tase
LLC_FLAGS=-O2

DEF_MODE_PERF         = -DNOVERIFY
DEF_MODE_REFERENCE    = -DNOTSX -DNOVERIFY
DEF_MODE_VERIFY_DUMMY = -DVERIFY_DUMMY
DEF_MODE=$(DEF_MODE_PERF)
EXTCPPFLAGS=$(CPPFLAGS) -I $(TASE_INCLUDES) $(DEF_MODE) -DSTANDALONE_APPLIB

#$(PROJECT_TASE_ALL): $(PROJECT_TASES) $(TASE_CORE)
#	cat $^ | sort | uniq > $@
# find $(TOP) -mindepth 2 -iname "*.tase" | xargs cat | LC_COLLATE=C sort | uniq > openssl.tase

# Overriding these particular files (across all of OpenSSL) to compile with sse/floating point support.
apps.bc speed.bc s_time.bc b_print.bc : private EXTCPPFLAGS+=-msse -msse2

$(LIBOBJ) $(E_OBJ): %.o: %.bc | $(PROJECT_TASE_ALL) $(TASE_MODELED)
	$(LLC) $(LLC_FLAGS) -tase-instrumented-functions $(PROJECT_TASE_ALL) $(TASE_MODELED_FLAGS) -o $*.s $<
	$(CC) $(CFLAGS) $(EXTCPPFLAGS) -Qunused-arguments -O2 -o $@ -c $*.s

tasescan: $(LIBOBJ:.o=.bc) $(E_OBJ:.o=.bc)
	@target=tasescan; $(RECURSIVE_MAKE)

$(LIBOBJ:.o=.bc) $(E_OBJ:.o=.bc): %.bc: %.c $(TASE_MODELED)
	$(CC) $(CFLAGS) $(EXTCPPFLAGS) -O0 -emit-llvm -o $*.init.bc -c $<
	$(DISAS) $*.init.bc
	$(OPT) -load $(TASE_PLUGIN_PATH) -function-wrapper -tase-instrumented-functions $*.tase $(TASE_MODELED_FLAGS) -o $@ $*.init.bc
	$(DISAS) $*.bc


