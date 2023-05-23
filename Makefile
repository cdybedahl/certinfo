PREFIX ?= /usr/local

compile:
	rebar3 escriptize

install:
	install -C _build/default/bin/certinfo $(PREFIX)/bin

all: compile install