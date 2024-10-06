# Author: Tomas Daniel
# Login:  xdanie14

CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -g
SRCS := main.cpp NetworkData.cpp Outputter.cpp CustomException.cpp
OBJS := $(SRCS:.cpp=.o)
EXE := isa-top

$(EXE): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -lncurses -lpcap -o $(EXE)

clean:
	rm -f $(EXE)

.PHONY: all clean
