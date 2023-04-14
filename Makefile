# Compiler name
cc := gcc

# Remove command
RM := rm -rf

# Source files
SOURCES := freertos-bridge.c

# Object files
OBJS := $(SOURCES:.c=.o)

# Main target
main: $(OBJS)
	$(CC) -shared -g -o libfreertos-bridge.so $^

%.o: %.c
	$(CC) -c -g -Wall -Werror -fPIC $< -o $@
 

.PHONY: clean
clean:
	$(RM) *.o *.so