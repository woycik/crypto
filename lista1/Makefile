CXX = g++
CXXFLAGS = -Wall -Wextra -O3 -march=native -funroll-loops -fomit-frame-pointer -flto \
           -fstrict-aliasing -ffast-math -fno-math-errno -fno-trapping-math -DNDEBUG
LDFLAGS = -flto

TARGETS = zad2 zad3

ZAD2_SRCS = md5.c zad2.cpp
ZAD3_SRCS = md5.c zad3.cpp zad3_main.cpp

all: $(TARGETS)

zad2: $(ZAD2_SRCS)
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(ZAD2_SRCS)

zad3: $(ZAD3_SRCS)
	@$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(ZAD3_SRCS)

clean:
	@$(RM) -f $(TARGETS) *.o *.exe
