all: ssl_survey

CC = gcc -g

ssl_survey: ssl_survey.o task.o
	$(CC) $^ -o ssl_survey 

ssl_survey.o: ssl_survey.c
	$(CC) -c ssl_survey.c

task.o: task.c task.h
	$(CC) -c task.c

clean:
	rm -rf *.o
