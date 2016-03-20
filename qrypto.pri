QT += xml

HEADERS += $$PWD/qrypto/qrypticstream.h \
           $$PWD/qrypto/qryptocipher.h \
           $$PWD/qrypto/qryptokeymaker.h

SOURCES += $$PWD/qrypto/qrypticstream.cpp \
           $$PWD/qrypto/qryptocipher.cpp \
           $$PWD/qrypto/qryptokeymaker.cpp

LIBS += -lcryptopp
