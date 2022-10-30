CC = gcc
CXX = g++ -std=c++11
CFLAGS = -fno-exceptions -fvisibility=hidden -DNDEBUG -DWEBRTC_POSIX -g
INC = -I.

.PHONY: libs
#libs:dsp base vad neteq codec
libs:base fec
# libs:dsp base vad

FECSRC = $(wildcard ulpfec/*.cc)
FECOBJS = $(FECSRC:%.cc=%.o)
FECLIB = libfec.a

BASESRC = $(wildcard rtc_base/*.cc)
BASEOBJS = $(BASESRC:%.cc=%.o)
BASELIB = libbase.a

fec:$(FECLIB)
base: $(BASELIB)


$(FECLIB): $(FECOBJS)
	ar cr $@ $^

$(BASELIB): $(BASEOBJS)
	ar cr $@ $^

$(FECOBJS): %.o: %.cc
	$(CXX) $(CFLAGS) -c $< -o $@ $(INC)

$(BASEOBJS): %.o: %.cc
	$(CXX) $(CFLAGS) -c $< -o $@ $(INC)

.PHONY: clean
clean:
	-rm $(FECOBJS) $(FECLIB) $(BASEOBJS) $(BASELIB)
