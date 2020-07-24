all: ssl_survey

CC = gcc -g
LIBS = `pkg-config --cflags --libs  openssl`
TRUST_STORE = /etc/ssl/certs/ca-certificates.crt

ssl_survey: ssl_survey.o task.o scan.o strbuf.o
	$(CC) $^ -o ssl_survey $(LIBS)
 
ssl_survey.o: ssl_survey.c
	$(CC) -c ssl_survey.c

task.o: task.c task.h
	$(CC) -c task.c

scan.o: scan.c scan.h
	$(CC) -DTRUST_STORE=\"$(TRUST_STORE)\" -c scan.c

strbuf.o: strbuf.c strbuf.h
	$(CC) -c strbuf.c

clean:
	rm -rf *.o
