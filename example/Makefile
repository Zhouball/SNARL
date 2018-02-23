all:
	g++ -std=c++14 -o echo_server EchoServer.cpp EchoHandler.cpp -lproxygenhttpserver -lfolly -lglog -lgflags -pthread

clean:
	rm echo_server