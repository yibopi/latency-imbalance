SUBDIRS = utils

bin_PROGRAMS = flipr

flipr_SOURCES = \
  icmp.cpp \
  listener.cpp \
  mac.cpp \
  net.cpp \
  patricia.cpp \
  status.cpp \
  subnet.cpp \
  subnet_list.cpp \
  trace.cpp \
  trace4.cpp \
  trace6.cpp \
  util.cpp \
  flipr.cpp \
  yconfig.cpp \
  graph.cpp \
  scheduler.cpp

include_HEADERS = \
  icmp.h \
  mac.h \
  patricia.h \
  random_list.h \
  stats.h \
  status.h \
  subnet.h \
  subnet_list.h \
  trace.h \
  ttlhisto.h \
  flipr.h \
  yconfig.h \
  graph.h \
  scheduler.h

man_MANS = \
  flipr.1 

EXTRA_DIST = \
  $(man_MANS) \
  LICENSE \
  CHANGES \
  ../analysis/yrp2warts.py

flipr.1.pdf:
	man -t ./flipr.1 | ps2pdf - > flipr.1.pdf
