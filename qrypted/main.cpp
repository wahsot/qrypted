#include "mainwindow.h"
#include <QApplication>
#include <QSettings>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QTranslator tr;
    a.setApplicationName("Qrypted");
    a.setApplicationVersion("2016.0402");

    for (QSettings settings; settings.isWritable(); ) {
        QVariant ln = settings.value("Language");

        for (QLocale lc(ln.toLocale()); ln.type() == QVariant::Locale; ln.clear()) {
            QLocale::setDefault(lc);
            tr.load(lc, a.applicationName().toLower(), ".",
                    a.applicationDirPath()) && a.installTranslator(&tr);
        }
        break;
    }

    MainWindow w;
    w.show();

    return a.exec();
}
