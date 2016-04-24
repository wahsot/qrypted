#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "../qrypto/qryptocipher.h"
#include "../qrypto/qryptocompress.h"
#include "../qrypto/qryptokeymaker.h"
#include "../qrypto/qrypticstream.h"
#include "../qrypto/sequre.h"

#include <QClipboard>
#include <QCloseEvent>
#include <QColorDialog>
#include <QDirIterator>
#include <QFile>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QProcess>
#include <QSaveFile>
#include <QSettings>
#include <QTextStream>
#include <QTranslator>

QMultiMap<QString, QTranslator*> MainWindow::getTranslators()
{
    static QMultiMap<QString, QTranslator*> translators;

    if (translators.isEmpty()) {
        QTranslator *translator = new QTranslator(qApp);

        foreach (const QString &dir, QDir::searchPaths("tr")) {
            // NOTE: simply using QDir("tr:") does not work,
            foreach (const QFileInfo &fi, QDir(dir, "*.qm", QDir::Size | QDir::Reversed)
                     .entryInfoList(QDir::Files | QDir::Readable)) {
                const QLocale lc(fi.completeBaseName().section('_', 1));

                if (lc != QLocale::c() && translator->load(fi.canonicalFilePath())) {
                    translators.insertMulti(lc.name(), translator);
                    translator = new QTranslator(qApp);
                }
            }
        }

        translator->deleteLater();
    }

    return translators;
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    QLocale l;
    ui->setupUi(this);

    Qrypto::Cipher cipher;
    Qrypto::KeyMaker keyMaker;

    foreach (const QString &name, Qrypto::Cipher::AlgorithmNames) {
        if (!name.isNull())
            ui->cipherComboBox->addItem(name);
    }

    foreach (const QString &name, Qrypto::Cipher::OperationCodes) {
        if (!name.isNull())
            ui->methodComboBox->addItem(name);
    }

    foreach (const QString &name, Qrypto::KeyMaker::AlgorithmNames) {
        if (!name.isNull())
            ui->digestComboBox->addItem(name);
    }

    setWindowTitle(qApp->applicationName());
    ui->formatToolBar->insertWidget(ui->actionBold, ui->fontComboBox);
    ui->formatToolBar->insertWidget(ui->actionBold, ui->fontSpinBox);
    ui->formatToolBar->insertSeparator(ui->actionBold);
    ui->cipherComboBox->setCurrentText(cipher.algorithmName());
    ui->digestComboBox->setCurrentText(keyMaker.algorithmName());
    ui->methodComboBox->setCurrentText(cipher.operationCode());
    ui->crypToolBar->addWidget(ui->passwordLineEdit);
    ui->crypToolBar->addWidget(ui->digestComboBox);
    ui->crypToolBar->addWidget(ui->cipherComboBox);
    ui->crypToolBar->addWidget(ui->methodComboBox);
    ui->passwordLineEdit->setInputMethodHints(Qt::ImhNoAutoUppercase | Qt::ImhNoPredictiveText | Qt::ImhSensitiveData);
    ui->searchToolBar->insertWidget(ui->actionFind_Previous, ui->findLineEdit);
    ui->searchToolBar->insertSeparator(ui->actionFind_Previous);
    ui->searchToolBar->hide();
    ui->textEdit->setFontFamily("monospace");
    ui->textEdit->setFontPointSize(10);
    ui->textEdit->setTextColor(ui->textEdit->textColor());
    ui->textEdit->document()->setDefaultFont(ui->textEdit->currentFont());
    m_editMenu = ui->textEdit->createStandardContextMenu();

    for (QList<QAction*> editActions = m_editMenu->actions(); !editActions.isEmpty(); editActions.clear()) {
        editActions.last()->setIcon(QIcon::fromTheme(QLatin1String("edit-select-all")));
        ui->menuEdit->insertActions(ui->menuEdit->actions().at(0), editActions);
        ui->mainToolBar->addActions(editActions.mid(0, editActions.size() - 3));
    }

    connect(ui->actionEnlarge_Font, SIGNAL(triggered()),
            ui->textEdit, SLOT(zoomIn()));
    connect(ui->actionFormatting_Toolbar, SIGNAL(triggered(bool)),
            ui->formatToolBar, SLOT(setVisible(bool)));
    connect(ui->actionItalic, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(setFontItalic(bool)));
    connect(ui->actionMain_Toolbar, SIGNAL(triggered(bool)),
            ui->mainToolBar, SLOT(setVisible(bool)));
    connect(ui->actionQuit, SIGNAL(triggered(bool)),
            this, SLOT(close()));
    connect(ui->actionShrink_Font, SIGNAL(triggered()),
            ui->textEdit, SLOT(zoomOut()));
    connect(ui->actionUnderline, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(setFontUnderline(bool)));
    connect(ui->findLineEdit, SIGNAL(returnPressed()),
            ui->actionFind_Next, SIGNAL(triggered()));
    connect(ui->fontComboBox, SIGNAL(currentFontChanged(QFont)),
            ui->textEdit, SLOT(setCurrentFont(QFont)));
    connect(ui->textEdit->document(), SIGNAL(modificationChanged(bool)),
            this, SLOT(setWindowModified(bool)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::getErrorString(const QFileDevice &fileDevice) const
{
    switch (fileDevice.error()) {
    case QFile::ReadError:
        return tr("An error occurred while reading from the file.");
    case QFile::WriteError:
        return tr("An error occurred while writing to the file.");
    case QFile::PermissionsError:
        return tr("The file could not be accessed.");
    case QFile::OpenError:
        return tr("The file could not be opened.");
    case QFile::ResourceError:
        return tr("A resource error occurred.");
    case QFile::FatalError:
        return tr("A fatal error occurred.");
    default:
        return fileDevice.errorString();
    }
}

QString MainWindow::getErrorString(const QryptIO &qryptic) const
{
    QString errorString;

    switch (qryptic.status()) {
    case QryptIO::KeyDerivationError:
        errorString = tr("key derivation", "This word will be used in the error sentence.");
        break;
    case QryptIO::CryptographicError:
        if (qryptic.device()->isWritable())
            errorString = tr("encryption", "This word will be used in the error sentence.");
        else
            errorString = tr("decryption", "This word will be used in the error sentence.");

        break;
    case QryptIO::CompressionError:
        errorString = tr("compression", "This word will be used in the error sentence.");
        break;
    default:
        return QString();
    }

    switch (qryptic.error()) {
    case Qrypto::NoError:
        return QString();
    case Qrypto::NotImplemented:
        return tr("Unknown %1 algorithm.").arg(errorString);
    case Qrypto::InvalidArgument:
        return tr("Unsupported %1 parameters.").arg(errorString);
    case Qrypto::IntegrityError:
        return tr("%1 data integrity test failed.").arg(errorString);
    case Qrypto::OutOfMemory:
        return tr("%1 memory allocation failed.").arg(errorString);
    case Qrypto::InvalidFormat:
        return tr("Invalid %1 format.").arg(errorString);
    default:
        return tr("An unknown %1 error occurred.").arg(errorString);
    }
}

bool MainWindow::openFile(const QString &fileName)
{
    if (fileName.isEmpty())
        return false;
    else if (!ui->textEdit->document()->isEmpty())
        return QProcess::startDetached(qApp->applicationFilePath(), QStringList() << fileName);

    const QFileInfo fileInfo(fileName);
    QFile loadFile(fileName);
    QryptIO qryptic(&loadFile);
    QLineEdit *password = ui->passwordLineEdit;
    Qrypto::SequreString pwd(password->text());
    Qrypto::SequreBytes data;

    for (QMessageBox::StandardButtons retry = QMessageBox::Retry, buttons = QMessageBox::NoButton;
         retry == QMessageBox::Retry; buttons = QMessageBox::NoButton) {
        QString errorString;
        retry = buttons;

        switch (qryptic.decrypt(*data, *pwd)) {
        case QryptIO::ReadPastEnd:
            // file error
            errorString = getErrorString(loadFile);
            buttons = QMessageBox::Retry | QMessageBox::Abort;
            break;
        case QryptIO::ReadCorruptData:
            // impossible to resolve
            if (qryptic.crypticVersion() < 0)
                errorString = tr("Unsupported file version.");
            else
                errorString = tr("Invalid file format.");

            buttons = QMessageBox::Ok;
            break;
        case QryptIO::Ok:
            for (QTextStream stream(*data); !stream.atEnd(); ) {
                // TODO: handle binary data?
                QAction *recent = 0;
                QDir::setCurrent(fileInfo.dir().path());
                ui->textEdit->setText(stream.readAll());
                ui->textEdit->document()->setBaseUrl(QUrl::fromLocalFile(fileInfo.filePath()));
                ui->textEdit->setWindowTitle(fileInfo.fileName() + QLatin1String("[*]"));

                if (qryptic.crypticVersion()) {
                    ui->digestComboBox->setCurrentText(qryptic.keyMaker().algorithmName());
                    ui->cipherComboBox->setCurrentText(qryptic.cipher().algorithmName());
                    ui->methodComboBox->setCurrentText(qryptic.cipher().operationCode());
                    password->setText(*pwd);
                } else {
                    password->clear();
                }

                if (stream.status() == QTextStream::Ok) {
                    if (!fileInfo.isWritable())
                        stream.setStatus(QTextStream::WriteFailed);
                } else {
                    QMessageBox::warning(this, tr("Warning"),
                                         tr("The file %1 was opened with %2 encoding but contained invalid characters.")
                                         .arg(fileName), QMessageBox::Close);
                }

                if ((stream.status() == QTextStream::Ok) == ui->actionRead_Only_Mode->isChecked())
                    ui->actionRead_Only_Mode->trigger();

                foreach (QAction *action, ui->menuOpen_Recent->actions()) {
                    const QFileInfo actionInfo(action->toolTip());

                    if (fileInfo == actionInfo)
                        recent = action;
                }

                if (recent) {
                    ui->menuOpen_Recent->removeAction(recent);
                } else {
                    recent = new QAction(fileInfo.fileName(), ui->menuOpen_Recent);
                    recent->setToolTip(fileInfo.filePath());
                    recent->setStatusTip(fileInfo.filePath());
                }

                ui->menuOpen_Recent->insertAction(ui->menuOpen_Recent->actions().at(0), recent);
                return true; // the only early-exit in the loop
            }
        default:
            errorString = getErrorString(qryptic);
            errorString[0] = errorString.at(0).toUpper();
            buttons = QMessageBox::Ok;

            switch (qryptic.error()) {
            case Qrypto::IntegrityError:
                if (qryptic.status() == QryptIO::KeyDerivationError ||
                    qryptic.status() == QryptIO::CryptographicError) {
                    bool ok;    // TODO: secure text dialog
                    pwd.assign(QInputDialog::getText(this, pwd->isEmpty()
                                                     ? tr("Enter your password")
                                                     : tr("Hash test failed. The password is wrong or the file is damaged."),
                                                     password->placeholderText(),
                                                     password->echoMode(),
                                                     *pwd, &ok, 0,
                                                     password->inputMethodHints()));
                    buttons = QMessageBox::NoButton;

                    if (ok && !pwd->isEmpty())
                        retry = QMessageBox::Retry;
                }
                break;
            case Qrypto::OutOfMemory:
                buttons = QMessageBox::Retry | QMessageBox::Abort;
                break;
            default: break;
            }
        }

        if (buttons != QMessageBox::NoButton)
            retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                          errorString, buttons);
    }

    return false;
}

bool MainWindow::saveFile(const QString &fileName)
{
    if (fileName.isEmpty())
        return false;

    const QFileInfo fileInfo(fileName);
    QSaveFile saveFile(fileName);
    QryptIO qryptic(&saveFile);
    QLineEdit *password = ui->passwordLineEdit;
    Qrypto::SequreString pwd(password->text());
    Qrypto::SequreBytes data;

    for (Qrypto::SequreString str; str->isEmpty(); str->toUtf8().swap(*data)) {
        const QString rich(QLatin1String("html htm xsi"));

        if (rich.split(' ').contains(fileInfo.suffix(), Qt::CaseInsensitive))
            str.assign(ui->textEdit->document()->toHtml());
        else
            str.assign(ui->textEdit->document()->toPlainText());
    }

    if (fileName.endsWith(QLatin1String("xsi"), Qt::CaseInsensitive)) {
        for (bool ok; pwd->isEmpty(); ) {
            pwd.assign(QInputDialog::getText(this, tr("Enter your password"),
                                             password->placeholderText(),
                                             password->echoMode(), QString(), &ok,
                                             0, Qt::ImhSensitiveData));

            if (ok)
                password->setText(*pwd);
            else
                return false;
        }

        qryptic.cipher().setAlgorithmName(ui->cipherComboBox->currentText());
        qryptic.cipher().setOperationCode(ui->methodComboBox->currentText());
        qryptic.keyMaker().setAlgorithmName(ui->digestComboBox->currentText());
        // TODO: make the following user configurable
        qryptic.keyMaker().setIterationTime(500);
        qryptic.keyMaker().setKeyBitSize(512);
        qryptic.compress().setAlgorithm(Qrypto::Compress::ZLib);
    } else {
        pwd.clear();
    }

    for (QMessageBox::StandardButtons retry = QMessageBox::Retry, buttons = QMessageBox::NoButton;
         retry == QMessageBox::Retry; buttons = QMessageBox::NoButton) {
        QString errorString;
        retry = buttons;

        switch (qryptic.encrypt(*data, *pwd)) {
        case QryptIO::KeyDerivationError:
        case QryptIO::CryptographicError:
        case QryptIO::CompressionError:
            errorString = getErrorString(qryptic);
            errorString[0] = errorString.at(0).toUpper();

            if (qryptic.error() == Qrypto::OutOfMemory)
                buttons = QMessageBox::Retry | QMessageBox::Abort;
            else
                buttons = QMessageBox::Ok;

            break;
        case QryptIO::Ok:
            if (saveFile.commit()) {
                QAction *recent = 0;
                QDir::setCurrent(fileInfo.dir().path());
                ui->textEdit->document()->setBaseUrl(QUrl::fromLocalFile(fileInfo.filePath()));
                ui->textEdit->document()->setModified(false);
                ui->textEdit->setWindowTitle(fileInfo.fileName() + QLatin1String("[*]"));

                if (recent) {
                    ui->menuOpen_Recent->removeAction(recent);
                } else {
                    recent = new QAction(fileInfo.fileName(), ui->menuOpen_Recent);
                    recent->setToolTip(fileInfo.filePath());
                    recent->setStatusTip(fileInfo.filePath());
                }

                ui->menuOpen_Recent->insertAction(ui->menuOpen_Recent->actions().at(0), recent);
                return true; // the only early-exit in the loop
            }
        default:
            // file error
            errorString = getErrorString(saveFile);
            buttons = QMessageBox::Retry | QMessageBox::Abort;
        }

        if (buttons != QMessageBox::NoButton)
            retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                          errorString, buttons);
    }

    return false;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (ui->textEdit->document()->isModified()) {
        if (QMessageBox::warning(this, trUtf8("Close — %1").arg(qApp->applicationName()),
                                 tr("The document %1 has been modified.\nDo you want to save your changes or discard them?")
                                 .arg(locale().quoteString(ui->textEdit->windowTitle())),
                                 QMessageBox::Save | QMessageBox::Discard) != QMessageBox::Discard) {
            on_actionSave_triggered();
            event->ignore();
            return;
        }
    }

    if (ui->actionFind->isChecked())
        ui->actionFind->trigger();

    const QList<QAction*> recent = ui->menuOpen_Recent->actions();
    QSettings settings;
    settings.beginGroup("MainWindow");
    settings.setValue("Geometry", saveGeometry());
    settings.setValue("State", saveState());
    settings.endGroup();
    settings.beginWriteArray("Recent Files", recent.size() - 2);

    for (int i = recent.size() - 2; i-- > 0; ) {
        settings.setArrayIndex(recent.size() - i);
        settings.setValue("Title", recent.at(i)->text());
        settings.setValue("Url", recent.at(i)->toolTip());
    }

    settings.endArray();
    QMainWindow::closeEvent(event);
}

void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);

    if (ui->textEdit->windowTitle().isEmpty()) {
        QList<QAction*> recent;
        QSettings settings;
        ui->textEdit->setWindowTitle(tr("Untitled") + QLatin1String("[*]"));
        settings.beginGroup("MainWindow");
        restoreGeometry(settings.value("Geometry").toByteArray());
        restoreState(settings.value("State").toByteArray());
        settings.endGroup();

        for (int i = settings.beginReadArray("Recent Files"); i-- > 0 && recent.size() < 10; ) {
            settings.setArrayIndex(i);
            QAction *action = new QAction(settings.value("Title").toString(), ui->menuOpen_Recent);
            action->setToolTip(settings.value("Url").toString());
            action->setStatusTip(action->toolTip());

            if (action->text().isEmpty() || action->toolTip().isEmpty())
                action->deleteLater();
            else
                recent.append(action);
        }

        ui->menuOpen_Recent->insertActions(ui->menuOpen_Recent->actions().at(0), recent);
        settings.endArray();

        foreach (const QString &arg, qApp->arguments().mid(1))
            openFile(arg);
    }
}

void MainWindow::on_actionAbout_Qt_triggered()
{
    QMessageBox::aboutQt(this, qobject_cast<QAction*>(sender())->toolTip());
}

void MainWindow::on_actionAbout_triggered()
{
    QMessageBox::about(this, qobject_cast<QAction*>(sender())->toolTip(),
                       trUtf8("%1 — Qt Cryptic Text Editor\nVersion %2\nVasthu Syahbani")
                       .arg(qApp->applicationName()).arg(qApp->applicationVersion()));
}

void MainWindow::on_actionAlign_Center_triggered(bool checked)
{
    if (checked) {
        ui->textEdit->setAlignment(Qt::AlignCenter);
        ui->actionAlign_Left->setChecked(false);
        ui->actionAlign_Right->setChecked(false);
    } else {
        ui->actionAlign_Center->setChecked(true);
    }
}

void MainWindow::on_actionAlign_Left_triggered(bool checked)
{
    if (checked) {
        ui->textEdit->setAlignment(Qt::AlignLeft);
        ui->actionAlign_Center->setChecked(false);
        ui->actionAlign_Right->setChecked(false);
    } else {
        ui->actionAlign_Left->setChecked(true);
    }
}

void MainWindow::on_actionAlign_Right_triggered(bool checked)
{
    if (checked) {
        ui->textEdit->setAlignment(Qt::AlignRight);
        ui->actionAlign_Center->setChecked(false);
        ui->actionAlign_Left->setChecked(false);
    } else {
        ui->actionAlign_Right->setChecked(true);
    }
}

void MainWindow::on_actionBold_triggered(bool checked)
{
    ui->textEdit->setFontWeight(50 + checked * 25);
}

void MainWindow::on_actionCensor_triggered(bool checked)
{
    if (checked)
        ui->textEdit->setTextBackgroundColor(ui->textEdit->textColor());
    else
        ui->textEdit->setTextBackgroundColor(Qt::transparent);
}

void MainWindow::on_actionFind_Next_triggered()
{
    !ui->findLineEdit->text().isEmpty() && ui->textEdit->find(ui->findLineEdit->text());
}

void MainWindow::on_actionFind_Previous_triggered()
{
    !ui->findLineEdit->text().isEmpty() && ui->textEdit->find(ui->findLineEdit->text(),
                                                              QTextDocument::FindBackward);
}

void MainWindow::on_actionFind_triggered(bool checked)
{
    ui->searchToolBar->setVisible(checked);
    ui->actionFind_Next->setEnabled(checked);
    ui->actionFind_Previous->setEnabled(checked);
    ui->findLineEdit->clear();
    ui->findLineEdit->setFocus();
}

void MainWindow::on_actionNew_triggered()
{
    QProcess::startDetached(qApp->applicationFilePath());
}

void MainWindow::on_actionOpen_triggered()
{
    openFile(QFileDialog::getOpenFileName(this, trUtf8("Open File — %1").arg(qApp->applicationName()),
                                          QString(),
                                          tr("Cryptic file (*.xsi);;HTML file (*.html *.htm);;Text file (*.txt)"),
                                          0, QFileDialog::DontUseNativeDialog));
}

void MainWindow::on_actionOverwrite_Mode_triggered(bool checked)
{
    ui->textEdit->setCursorWidth(checked * ui->textEdit->fontMetrics().averageCharWidth() + 1);
    ui->textEdit->setOverwriteMode(checked);
}

void MainWindow::on_actionRead_Only_Mode_triggered(bool checked)
{
    ui->textEdit->setTextInteractionFlags(checked
                                          ? Qt::TextEditorInteraction
                                          : Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
}

void MainWindow::on_actionReload_triggered()
{
    const QString fileName = ui->textEdit->document()->baseUrl().toLocalFile();
    ui->textEdit->clear();
    openFile(fileName);
}

void MainWindow::on_actionSave_As_triggered()
{
    saveFile(QFileDialog::getSaveFileName(this,
                                          trUtf8("Save File — %1").arg(qApp->applicationName()),
                                          QString(),
                                          tr("Cryptic file (*.xsi);;HTML file (*.html *.htm);;Text file (*.txt)"),
                                          0, QFileDialog::DontUseNativeDialog));
}

void MainWindow::on_actionSave_triggered()
{
    const QString fileName = ui->textEdit->document()->baseUrl().toLocalFile();

    if (fileName.isEmpty())
        on_actionSave_As_triggered();
    else
        saveFile(fileName);
}

void MainWindow::on_actionSwitch_Application_Language_triggered()
{
    const QMultiMap<QString, QTranslator*> translators = getTranslators();
    const QLocale current;
    QMap<QString, QString> languages;
    bool ok;

    foreach (const QString &name, translators.uniqueKeys())
        languages[QLocale(name).nativeLanguageName()] = name;

    QString l = QInputDialog::getItem(this,
                                      ui->actionSwitch_Application_Language->toolTip(),
                                      tr("Language"), languages.keys(),
                                      languages.keys().indexOf(current.nativeLanguageName()),
                                      false, &ok);

    if (ok && current.nativeLanguageName() != l) {
        const QLocale lc(languages.value(l));
        QSettings settings;
        settings.setValue(QLatin1String("Language"), lc.name());

        foreach (QTranslator *tr, translators.values(current.name()))
            qApp->removeTranslator(tr);

        foreach (QTranslator *tr, translators.values(lc.name()))
            qApp->installTranslator(tr);

        QMessageBox::information(this, tr("Application Language Changed"),
                                 tr("The language for this application has been changed."
                                    "The change will take effect the next time the application is started."));

        QLocale::setDefault(lc);
        ui->retranslateUi(this);
        m_editMenu->deleteLater();
        m_editMenu = ui->textEdit->createStandardContextMenu();

        for (QList<QAction*> editActions = m_editMenu->actions(); !editActions.isEmpty(); editActions.clear()) {
            editActions.last()->setIcon(QIcon::fromTheme(QLatin1String("edit-select-all")));
            ui->menuEdit->insertActions(ui->menuEdit->actions().at(0), editActions);
            ui->mainToolBar->addActions(editActions.mid(0, editActions.size() - 3));
        }
    }
}

void MainWindow::on_actionText_Color_triggered()
{
    const QColor c = QColorDialog::getColor(ui->textEdit->textColor(), this,
                                            trUtf8("Select Colour — %1").arg(qApp->applicationName()));

    if (c.isValid())
        ui->textEdit->setTextColor(c);
}

void MainWindow::on_actionText_Highlight_triggered()
{
    const QColor c = QColorDialog::getColor(ui->textEdit->textBackgroundColor(), this,
                                            trUtf8("Select Colour — %1").arg(qApp->applicationName()));

    if (c.isValid())
        ui->textEdit->setTextBackgroundColor(c);
}

void MainWindow::on_actionWord_Wrap_triggered(bool checked)
{
    ui->textEdit->setWordWrapMode(QTextOption::WrapMode(checked));
}

void MainWindow::on_fontSpinBox_valueChanged(int value)
{
    ui->textEdit->setFontPointSize(value);
}

void MainWindow::on_textEdit_currentCharFormatChanged(const QTextCharFormat &format)
{
    ui->actionBold->setChecked(format.fontWeight() > 50);
    ui->actionCensor->setChecked(format.foreground().color().alpha() == 0);
    ui->actionItalic->setChecked(format.fontItalic());
    ui->actionUnderline->setChecked(format.fontUnderline());
    ui->fontComboBox->setCurrentFont(format.font());
    ui->fontSpinBox->setValue(format.fontPointSize());
}

void MainWindow::on_textEdit_cursorPositionChanged()
{
    const QTextCursor cursor = ui->textEdit->textCursor();
    const QTextBlockFormat fmt = cursor.blockFormat();
    const Qt::Alignment align = fmt.alignment();
    ui->actionAlign_Center->setChecked(align & Qt::AlignCenter);
    ui->actionAlign_Left->setChecked(align & Qt::AlignLeft);
    ui->actionAlign_Right->setChecked(align & Qt::AlignRight);

    ui->statusBar->showMessage(tr("%1 : Line %2 : Column %3")
                               .arg(ui->textEdit->document()->baseUrl().toDisplayString())
                               .arg(cursor.blockNumber() + 1)
                               .arg(cursor.columnNumber() + 1));
}

void MainWindow::on_textEdit_windowTitleChanged()
{
    on_textEdit_cursorPositionChanged();
    setWindowTitle(QString("%1 — %3")
                   .arg(ui->textEdit->windowTitle())
                   .arg(qApp->applicationName()));
}
