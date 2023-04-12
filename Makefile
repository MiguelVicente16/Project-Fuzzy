# Define the compiler and compilation flags
CC = gcc
CFLAGS = -std=gnu17
CFLAGS += -Wall
CFLAGS += -Wshadow
CFLAGS += -Wextra
CFLAGS += -fstack-protector-all
CFLAGS += -g

# Define the name of the executable
EXEC=fuzzer

# Define the names of directories for object files and source files
OBJDIR = obj
SRCDIR = src

# The default target, which is the executable fuzzer
all: objdir $(EXEC)

# A target to build the fuzzer executable
fuzzer: $(OBJDIR)/main.o $(OBJDIR)/tar.o $(OBJDIR)/fuzzer.o $(OBJDIR)/test.o
	$(CC) -o $(EXEC) $^ $(CFLAGS)

# A target to create the object directory if it doesn't exist
objdir:
	mkdir -p $(OBJDIR)

# A rule to compile each .c file into an object file
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) -o $@ -c $< $(CFLAGS)

# A target to clean up the object files
clean_obj:
	rm -rf $(OBJDIR)

# A target to clean up the object files and the executable and generated files
clean:
	rm -rf $(EXEC) help $(OBJDIR)

# A target to clean up generated success files
clean_succ:
	rm -rf success_* *.txt

# A target to clean up missed files
clean_trash:
	rm -rf *.txt