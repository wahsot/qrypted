include($$PWD/qrypto.pri)

LIBS += -lcryptopp

SOURCES += $$PWD/cryptopp/qryptocipher.cpp \
           $$PWD/cryptopp/qryptocompress.cpp \
           $$PWD/cryptopp/qryptokeymaker.cpp
