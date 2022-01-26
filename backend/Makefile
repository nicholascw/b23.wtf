COMPILERFLAGS = -O2 -fPIC -Wall -Wextra -lpthread -g
SERVEROBJECTS = obj/server.o
.PHONY: all clean

all : obj b23_broker

b23_broker: $(SERVEROBJECTS)
	$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)
	objcopy --only-keep-debug $@ $@.debug && objcopy --strip-debug $@ && objcopy --add-gnu-debuglink $@.debug $@

clean :
	$(RM) vgcore.* obj/*.o b23_broker

obj/%.o: src/%.c
	$(CC) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj

