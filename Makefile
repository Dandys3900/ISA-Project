CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -g
SRCS := main.cpp NetworkData.cpp Outputter.cpp
OBJS := $(SRCS:.cpp=.o)
EXE := isa-top

$(EXE): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(EXE) -lpcap

clean:
	rm -f $(EXE)

.PHONY: all clean
