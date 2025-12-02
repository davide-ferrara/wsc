PROGRAM_NAME := wsc

main:
	gcc -lc -lpthread main.c wsc.c log.c http.c -DLOG_USE_COLOR -o $(PROGRAM_NAME)

run: main
	./$(PROGRAM_NAME)

clean:
	rm $(PROGRAM_NAME)
