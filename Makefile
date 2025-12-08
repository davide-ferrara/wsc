PROGRAM_NAME := wsc
FLAGS := -W -Wall -O2 -DLOG_USE_COLOR

main:
	gcc -lc -lpthread main.c wsc.c log.c http.c sds.c $(FLAGS) -o $(PROGRAM_NAME)

run: main
	./$(PROGRAM_NAME)

clean:
	rm $(PROGRAM_NAME) log.txt
