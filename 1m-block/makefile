TARGET = 1m-block
SRC = main.cpp
OBJ = main.o
CXX = g++
CXXFLAGS = -std=c++17 -O2
LIBS = -lnetfilter_queue

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJ)
