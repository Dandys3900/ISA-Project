CXX := g++
CXXFLAGS := -std=c++20 -Wall -Wextra -g
SRCS := main.cpp NetworkData.cpp Outputter.cpp CustomException.cpp
OBJS := $(SRCS:.cpp=.o)
EXE := isa-top
LIBS := -lpcap -lncurses

$(EXE): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(EXE) $(LIBS)

clean:
	rm -f $(EXE)

.PHONY: all clean
