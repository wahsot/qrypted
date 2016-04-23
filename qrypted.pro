QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = qrypted
TEMPLATE = app
DESTDIR = $$PWD/bin
UI_DIR = $$PWD/build
OBJECTS_DIR = $$UI_DIR
MOC_DIR = $$UI_DIR
RCC_DIR = $$UI_DIR

#include(qrypto/botan.pri)
include(qrypto/cryptopp.pri)

SOURCES   += $$PWD/qrypted/main.cpp \
             $$PWD/qrypted/mainwindow.cpp

HEADERS   += $$PWD/qrypted/mainwindow.h \

FORMS     += $$PWD/qrypted/mainwindow.ui

RESOURCES += $$PWD/qrypted/resource.qrc

TRANSLATIONS += $$PWD/qrypted/translations/qrypted_de.ts \
                $$PWD/qrypted/translations/qrypted_fr.ts \
                $$PWD/qrypted/translations/qrypted_en.ts \
                $$PWD/qrypted/translations/qrypted_es.ts \
                $$PWD/qrypted/translations/qrypted_ja.ts \
                $$PWD/qrypted/translations/qrypted_ru.ts \
                $$PWD/qrypted/translations/qrypted_zh.ts
