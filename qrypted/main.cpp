#include "mainwindow.h"

#include <QApplication>
#include <QDir>
#include <QSettings>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QTranslator tr;
    a.setApplicationName("Qrypted");
    a.setApplicationVersion("2016.0410");
    a.setOrganizationDomain("qrypted.org");
    a.setOrganizationName("Qrypted");

    for (QSettings settings; settings.isWritable(); ) {
        QVariant ln = settings.value("Language");

        for (QLocale lc(ln.toLocale()); ln.type() == QVariant::Locale; ln.clear()) {
            QLocale::setDefault(lc);
            QDir dir(a.applicationDirPath());
            dir.cd("../share/translations") && \
            tr.load(lc, a.applicationName().toLower(), ".", dir.canonicalPath()) && \
            a.installTranslator(&tr);
        }
        break;
    }

    MainWindow w;
    w.show();

    return a.exec();
}
