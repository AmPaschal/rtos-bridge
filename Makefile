#compiler name
cc := gcc
CFLAGS = -g

#remove command
RM := rm -rf

#source files
SOURCES := freertos-bridge.c ../packetdrill/gtests/net/packetdrill/test.c

#object files
OBJS := $(SOURCES:.c=.o)

#main target
main: $(OBJS)
	$(CC) -shared -g -o libfreertos-bridge.so $^

%.o: %.c
	$(CC) -c -g -Wall -Werror -fPIC $< -o $@
 

.PHONY: clean
clean:
	$(RM) *.o *.so