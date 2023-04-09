CC = gcc
CFLAGS = -std=gnu17
CFLAGS += -Wall
# CFLAGS += -Werror
CFLAGS += -Wshadow
CFLAGS += -Wextra
CFLAGS += -fstack-protector-all
CFLAGS += -g

EXEC=fuzzer

OBJDIR = obj
SRCDIR = src

all: objdir $(EXEC)

help: $(OBJDIR)/help.o
	$(CC) -o $@ $^ $(CFLAGS)

fuzzer: $(OBJDIR)/main.o $(OBJDIR)/tar.o $(OBJDIR)/fuzzer.o
	$(CC) -o $(EXEC) $^ $(CFLAGS)

objdir:
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -rf $(OBJDIR)

mrproper: clean succ
	rm -rf $(EXEC) help $(OBJDIR)

succ:
	rm -rf success_* *.dat