# Author: Tomas Daniel
# Login:  xdanie14

CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra
SRCS := main.cpp NetworkData.cpp Outputter.cpp
OBJS := $(SRCS:.cpp=.o)
EXE := isa-top

$(EXE): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -lpthread -lncurses -lpcap -o $(EXE)

clean:
	rm -f $(EXE)

.PHONY: all clean
