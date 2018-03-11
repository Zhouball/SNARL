CPP = g++
LIBS = -lcrypto -lssl -lmysqlcppconn
PATHS = -I/usr/include/boost

default:
	g++ server.cpp $(LIBS) $(PATHS) -std=c++11 -o server
