CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -g
SRCS := main.cpp NetworkData.cpp Outputter.cpp CustomException.cpp
OBJS := $(SRCS:.cpp=.o)
EXE := isa-top

$(EXE): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(EXE) -lpcap -lncurses

clean:
	rm -f $(EXE)

.PHONY: all clean
