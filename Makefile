
SASL_INC ?= /usr/include/sasl

SASL_LIBDIR ?= /usr/lib/sasl2
ifeq ("$(wildcard /usr/lib/x86_64-linux-gnu/sasl2)","")
else
	SASL_LIBDIR := /usr/lib/x86_64-linux-gnu/sasl2
endif

CFLAGS  := -fPIC -I$(SASL_INC) -Wall -O2
LDFLAGS := -shared -lsasl2

TARGET  := 00-simple-xoauth2.so
SRC     := src/xoauth2.c xoauth_common.o

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

xoauth_common.o: src/xoauth_common.c src/xoauth_common.h
	$(CC) $(CFLAGS) -c src/xoauth_common.c -o xoauth_common.o

install: $(TARGET)
	install -m 644 $(TARGET) $(SASL_LIBDIR)

clean:
	rm -f $(TARGET) xoauth_common.o

