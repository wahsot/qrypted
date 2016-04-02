include($$PWD/qrypto.pri)

LIBS += -lbotan

SOURCES += $$PWD/botan/qryptocipher.cpp \
           $$PWD/botan/qryptocompress.cpp \
           $$PWD/botan/qryptokeymaker.cpp
