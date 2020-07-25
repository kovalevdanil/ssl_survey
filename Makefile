all: ssl_survey

CC = gcc -g -Wall
LIBS = `pkg-config --cflags --libs  openssl` -pthread
TRUST_STORE = /etc/ssl/certs/ca-certificates.crt

ssl_survey: ssl_survey.o task.o scan.o strbuf.o thread_pool.o
	$(CC)  $^ -o ssl_survey $(LIBS)
 
ssl_survey.o: ssl_survey.c
	$(CC) -c ssl_survey.c

task.o: task.c task.h
	$(CC) -c task.c

scan.o: scan.c scan.h
	$(CC) -DTRUST_STORE=\"$(TRUST_STORE)\" -c scan.c

strbuf.o: strbuf.c strbuf.h
	$(CC) -c strbuf.c

thread_pool.o: thread_pool.c thread_pool.h
	$(CC) -c thread_pool.c 

clean:
	rm -rf *.o
