all:
	g++ -std=c++14 -o snarl_server SNARLServer.cpp SNARLHandler.cpp -lproxygenhttpserver -lfolly -lglog -lgflags -pthread

clean:
	rm snarl_server