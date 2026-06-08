# ---- Configuration ----

SASL_INC ?= /usr/include/sasl

SASL_LIBDIR ?= /usr/lib/sasl2
ifeq ("$(wildcard /usr/lib/x86_64-linux-gnu/sasl2)","")
else
	SASL_LIBDIR := /usr/lib/x86_64-linux-gnu/sasl2
endif

CFLAGS  := -fPIC -I$(SASL_INC) -Wall -O2
LDFLAGS := -shared -lsasl2

TARGET  := 00-simple-xoauth2.so
SRC     := xoauth2.c xoauth_common.o

# ---- Build static helper ----

xoauth_common.o: xoauth_common.c xoauth_common.h
	$(CC) $(CFLAGS) -c xoauth_common.c -o xoauth_common.o

# ---- Build plugin ----

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ xoauth2.c xoauth_common.o $(LDFLAGS)

# ---- Install ----

install: $(TARGET)
	install -m 644 $(TARGET) $(SASL_LIBDIR)
	@echo "#Installed $(TARGET) to $(SASL_LIBDIR)"

# ---- Clean ----

clean:
	rm -f $(TARGET) xoauth_common.o

