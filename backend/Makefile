COMPILERFLAGS = -O2 -fPIC -Wall -Wextra -pthread
DBGFLAGS = -g -DDEBUG
SERVEROBJECTS = obj/server.o
LINKLIBS=
.PHONY: all clean

all : b23_broker

b23_broker: $(SERVEROBJECTS)
	$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)

b23_broker_dbg: $(SERVEROBJECTS)
	$(CC) $(DBGFLAGS) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)

clean:
	$(RM) vgcore.* obj/*.o b23_broker b23_broker_dbg

obj/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) $(COMPILERFLAGS) -c -o $@ $<

