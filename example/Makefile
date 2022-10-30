CC = gcc
CXX = g++ -std=c++11
CFLAGS = -fno-exceptions -fvisibility=hidden -DNDEBUG -DWEBRTC_POSIX -g
INCPATH = -I. -I../
LIBPATH = -L. -L..


.PHONY: app
app:fec

ULP_FEC=ulpfec

fec: $(ULP_FEC)

ulpfec: fecfuzz.cc
	$(CXX) $< -o $@ $(INCPATH) $(LIBPATH) -lbase -lfec -g
.PHONY: clean
clean:
	-rm $(ULP_FEC)
