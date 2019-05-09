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
    a.setApplicationVersion("2019.0508");
    a.setOrganizationDomain("qrypted.org");
    a.setOrganizationName("Qrypted");
    QDir::addSearchPath("tr", a.applicationDirPath() + QLatin1String("/../share/translations"));
    QDir::addSearchPath("tr", QLibraryInfo::location(QLibraryInfo::TranslationsPath));

    for (QSettings settings; settings.isWritable(); ) {
        QLocale lc(settings.value("Language").toString());

        if (lc == QLocale::c())
            lc = QLocale::system();
        else
            QLocale::setDefault(lc);

        foreach (QTranslator *tr, MainWindow::getTranslators().values(lc.name()))
            qApp->installTranslator(tr);

        break;
    }

    MainWindow w;
    w.show();

    return a.exec();
}
