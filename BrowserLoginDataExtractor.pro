QT -= gui
QT += sql

CONFIG += c++11 console
CONFIG -= app_bundle

QMAKE_CXXFLAGS += -Wextra -pedantic

TARGET = BrowserLoginDataExtractor
TEMPLATE = app

LIBS += -lcrypt32

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        GlobalDefinitions/console.cpp \
        main.cpp \
        worker.cpp

HEADERS += \
    GlobalDefinitions/console.h \
    worker.h

!contains(QT_ARCH, x86_64){
    LIBS += -LC:/OpenSSL/OpenSSL-Win32/lib/ -llibcrypto
    INCLUDEPATH += C:/OpenSSL/OpenSSL-Win32/include
    DEPENDPATH += C:/OpenSSL/OpenSSL-Win32/include
    message("Compiling for 32bit system")
} else {
    LIBS += -LC:/OpenSSL/OpenSSL-Win64/lib/ -llibcrypto
    INCLUDEPATH += C:/OpenSSL/OpenSSL-Win64/include
    DEPENDPATH += C:/OpenSSL/OpenSSL-Win64/include
    message("Compiling for 64bit system")
}
