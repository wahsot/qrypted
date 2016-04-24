#include "mainwindow.h"

#include <QApplication>
#include <QDir>
#include <QLibraryInfo>
#include <QSettings>
#include <QTranslator>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationName("Qrypted");
    a.setApplicationVersion("2016.0410");
    a.setOrganizationDomain("qrypted.org");
    a.setOrganizationName("Qrypted");
    QDir::addSearchPath("tr", a.applicationDirPath() + QLatin1String("/../share/translations"));
    QDir::addSearchPath("tr", QLibraryInfo::location(QLibraryInfo::TranslationsPath));

    for (QSettings settings; settings.isWritable(); ) {
        for (QLocale lc(settings.value("Language").toString()); lc != QLocale::c(); ) {
            foreach (QTranslator *tr, MainWindow::getTranslators().values(lc.name()))
                qApp->installTranslator(tr);

            QLocale::setDefault(lc);
            break;
        }
        break;
    }

    MainWindow w;
    w.show();

    return a.exec();
}
