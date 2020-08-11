# all: ssl_survey

# CC = gcc -g -Wall -std=c99 
# LIBS = `pkg-config --cflags --libs  openssl libuv`  
# # TRUST_STORE = /etc/ssl/certs/ca-certificates.crt

# SRC = $(wildcard *.c)
# OBJ = $(patsubst %.c, %.o, $(SRC))
# DEP = $(patsubst %.c, %.o, $(SRC))
# PROG = $(patsubst %.c, %, $(SRC))
# OUTPUT = ssl_survey
# TRUST_DEF =

# ifneq ($(MAKECMDGOALS), clean)
# 	-include $(OBJ:.o=.d)
# endif

# ifdef TRUST_STORE
# 	TRUST_DEF=-DTRUST_STORE=\"$(TRUST_STORE)\"
# endif 

# ssl_survey: $(OBJ)
# 	@$(CC) $^ -o $(OUTPUT) $(LIBS)
 
# scan.o: scan.c scan.h strbuf.h
# 	@$(CC) $(TRUST_DEF) -c scan.c

# %.o %.d: %.c
# 	@$(CC) -c $< -o $@  

# clean:
# 	$(RM) $(OBJ) 

# %.d : %.c
# 	@$(CC) -MM $(CFLAGS) $< | sed 's/\($*\)\.o[ :]*/\1.o $@ : /g' > $@ 		

# % : %.c
 
all: ssl_survey

CC = gcc -g -Wall -std=c99 
LIBS = `pkg-config --cflags --libs  openssl libuv`  
# TRUST_STORE = /etc/ssl/certs/ca-certificates.crt

SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
DEP = $(SRC:.c=.d) 
OUTPUT = ssl_survey
TRUST_DEF =

ifdef TRUST_STORE
	TRUST_DEF=-DTRUST_STORE=\"$(TRUST_STORE)\"
endif 

ifneq ($(MAKECMDGOALS),clean)

%.d: %.c
	@$(CC) -MM $*.c >> $*.d

-include $(DEP)
endif 

ssl_survey: $(OBJ)
	$(CC) $^ -o $(OUTPUT) $(LIBS)
 
scan.o: scan.c 
	@$(CC)  $(TRUST_DEF) -c scan.c

%.o: %.c
	@$(CC) -c $< -o $@  

clean:
	$(RM) $(OBJ) $(DEP)
