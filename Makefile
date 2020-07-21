all: ssl_survey

CC = gcc -g
LIBS = `pkg-config --libs openssl`

ssl_survey: ssl_survey.o task.o skan.o
	$(CC) $^ -o ssl_survey $(LIBS)
 
ssl_survey.o: ssl_survey.c
	$(CC) -c ssl_survey.c

task.o: task.c task.h
	$(CC) -c task.c

skan.o: skan.c skan.h
	$(CC) -c skan.c

clean:
	rm -rf *.o
