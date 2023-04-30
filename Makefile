all: Monitori

Monitori: Main.o Packet.o resources.o rules.o
	gcc -o Monitori Main.o Packet.o resources.o rules.o -g -lpthread
	
Main.o: Main.c resources.c rules.c Packet.c
	gcc -c resources.c -g
	gcc -c rules.c -g
	gcc -c Packet.c -g
	gcc -c Main.c -g -lpthread
	
Packet.o: Packet.c rules.c Main.c
	gcc -c rules.c -g
	gcc -c Packet.c -g
	gcc -c Main.c -g
	
resources.o: resources.c
	gcc -c resources.c -g
	
rules.o: rules.c
	gcc -c rules.c -g
