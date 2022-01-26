COMPILERFLAGS = -O2 -fPIC -Wall -Wextra -pthread
SERVEROBJECTS = obj/server.o
.PHONY: all clean

all : obj b23_broker

b23_broker: $(SERVEROBJECTS)
	$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)

clean :
	$(RM) vgcore.* obj/*.o b23_broker

obj/%.o: src/%.c
	$(CC) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj

