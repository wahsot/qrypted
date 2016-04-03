# DO NOT INCLUDE THIS FILE
# include either botan.pri or cryptopp.pri
QT += xml

HEADERS += $$PWD/pointerator.h \
           $$PWD/qrypto.h \
           $$PWD/qrypticstream.h \
           $$PWD/qryptocipher.h \
           $$PWD/qryptocompress.h \
           $$PWD/qryptokeymaker.h \
           $$PWD/sequre.h

SOURCES += $$PWD/qrypticstream.cpp \
           $$PWD/sequre.cpp
