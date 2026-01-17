CXX = g++
CXXFLAGS = -Wall -std=c++17 -pthread

all: echo-server echo-client

echo-server: echo-server.cpp
	$(CXX) $(CXXFLAGS) -o echo-server echo-server.cpp

echo-client: echo-client.cpp
	$(CXX) $(CXXFLAGS) -o echo-client echo-client.cpp

clean:
	rm -f echo-server echo-client
