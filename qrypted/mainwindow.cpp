#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "../qrypto/qryptocipher.h"
#include "../qrypto/qryptokeymaker.h"
#include "../qrypto/qrypticstream.h"

#include <QBuffer>
#include <QClipboard>
#include <QColorDialog>
#include <QFile>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QMimeData>
#include <QProcess>
#include <QSaveFile>
#include <QSettings>
#include <QTextStream>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    QLocale l;
    ui->setupUi(this);

    for (int i = 6; i < 16; ++i)
        ui->sizeComboBox->addItem(l.toString(i), i);

    for (int i = 16; i < 33; i += 2)
        ui->sizeComboBox->addItem(l.toString(i), i);

    Qrypto::Cipher cipher;
    ui->cipherComboBox->addItems(Qrypto::Cipher::AlgorithmNames);
    ui->cipherComboBox->removeItem(ui->cipherComboBox->count() - 1);
    ui->methodComboBox->addItems(Qrypto::Cipher::OperationCodes);
    ui->methodComboBox->removeItem(ui->methodComboBox->count() - 1);

    setWindowTitle(qApp->applicationName());
    ui->actionAbout->setText(ui->actionAbout->text().arg(qApp->applicationName()));
    ui->sizeComboBox->setCurrentIndex(6);
    ui->formatToolBar->insertWidget(ui->actionBold, ui->fontComboBox);
    ui->formatToolBar->insertWidget(ui->actionBold, ui->sizeComboBox);
    ui->formatToolBar->insertSeparator(ui->actionBold);
    ui->cipherComboBox->setCurrentText(cipher.algorithmName());
    ui->methodComboBox->setCurrentText(cipher.operationCode());
    ui->crypToolBar->addWidget(ui->passwordLineEdit);
    ui->crypToolBar->addWidget(ui->cipherComboBox);
    ui->crypToolBar->addWidget(ui->methodComboBox);
    ui->searchToolBar->insertWidget(ui->actionFind_Previous, ui->findLineEdit);
    ui->searchToolBar->insertSeparator(ui->actionFind_Previous);
    ui->searchToolBar->hide();
    ui->textEdit->setFontFamily("monospace");
    ui->textEdit->setFontPointSize(10);
    ui->textEdit->document()->setDefaultFont(ui->textEdit->font());

    connect(qApp->clipboard(), SIGNAL(dataChanged()),
            this, SLOT(clipboard_dataChanged()));
    connect(ui->actionCopy, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(copy()));
    connect(ui->actionCut, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(cut()));
    connect(ui->actionEnlarge_Font, SIGNAL(triggered()),
            ui->textEdit, SLOT(zoomIn()));
    connect(ui->actionFormatting_Toolbar, SIGNAL(triggered(bool)),
            ui->formatToolBar, SLOT(setVisible(bool)));
    connect(ui->actionItalic, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(setFontItalic(bool)));
    connect(ui->actionMain_Toolbar, SIGNAL(triggered(bool)),
            ui->mainToolBar, SLOT(setVisible(bool)));
    connect(ui->actionPaste, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(paste()));
    connect(ui->actionRedo, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(redo()));
    connect(ui->actionSelect_All, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(selectAll()));
    connect(ui->actionShrink_Font, SIGNAL(triggered()),
            ui->textEdit, SLOT(zoomOut()));
    connect(ui->actionUnderline, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(setFontUnderline(bool)));
    connect(ui->actionUndo, SIGNAL(triggered(bool)),
            ui->textEdit, SLOT(undo()));
    connect(ui->findLineEdit, SIGNAL(returnPressed()),
            ui->actionFind_Next, SIGNAL(triggered()));
    connect(ui->fontComboBox, SIGNAL(currentFontChanged(QFont)),
            ui->textEdit, SLOT(setCurrentFont(QFont)));
    connect(ui->textEdit, SIGNAL(copyAvailable(bool)),
            ui->actionCopy, SLOT(setEnabled(bool)));
    connect(ui->textEdit, SIGNAL(copyAvailable(bool)),
            ui->actionCut, SLOT(setEnabled(bool)));
    connect(ui->textEdit, SIGNAL(redoAvailable(bool)),
            ui->actionRedo, SLOT(setEnabled(bool)));
    connect(ui->textEdit, SIGNAL(undoAvailable(bool)),
            ui->actionUndo, SLOT(setEnabled(bool)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::openFile(const QString &fileName)
{
    if (fileName.isEmpty())
        return false;
    else if (!ui->textEdit->document()->isEmpty())
        return QProcess::startDetached(qApp->applicationFilePath(), QStringList() << fileName);

    QFile loadFile(fileName);

    for (int retry = QMessageBox::Retry; retry == QMessageBox::Retry; loadFile.reset()) {
        QryptIO qryptic(&loadFile);
        QLineEdit *password = ui->passwordLineEdit;
        QByteArray data;
        QString errorString;

        switch (qryptic.read(data, password->text())) {
        case QryptIO::ReadPastEnd:
            // file error
            switch (loadFile.error()) {
            case QFile::PermissionsError:
                errorString = tr("The file could not be accessed.");
                break;
            case QFile::OpenError:
                errorString = tr("The file could not be opened.");
                break;
            case QFile::ResourceError:
                errorString = tr("A resource error occurred.");
                break;
            case QFile::FatalError:
                errorString = tr("A fatal error occurred.");
                break;
            default:
                errorString = tr("An error occured while reading from the file.");
            }

            retry = QMessageBox::critical(this, tr("Error"), errorString,
                                      QMessageBox::Retry | QMessageBox::Abort);
            break;
        case QryptIO::ReadCorruptData:
            // impossible to resolve
            if (qryptic.crypticVersion() < 0)
                errorString = tr("Unsupported file version.");
            else
                errorString = tr("Invalid file format.");

            retry = QMessageBox::critical(this, tr("Error"), errorString);
        case QryptIO::Ok: {
            QTextStream stream(data); // TODO: handle binary data?
            const QFileInfo fileInfo(fileName);
            QDir::setCurrent(fileInfo.dir().path());
            ui->textEdit->setText(stream.readAll());
            ui->textEdit->document()->setMetaInformation(QTextDocument::DocumentUrl, fileInfo.filePath());
            ui->textEdit->setWindowTitle(fileInfo.fileName());

            if (qryptic.crypticVersion()) {
                ui->cipherComboBox->setCurrentText(qryptic.cipher().algorithmName());
                ui->methodComboBox->setCurrentText(qryptic.cipher().operationCode());
            } else {
                ui->passwordLineEdit->clear();
            }

            if (stream.status() == QTextStream::Ok) {
                if (ui->actionRead_Only_Mode->isChecked())
                    ui->actionRead_Only_Mode->trigger();
            } else {
                QMessageBox::warning(this, tr("Warning"),
                                     tr("The file %1 was opened with %2 encoding but contained invalid characters.")
                                     .arg(fileName), QMessageBox::Close);

                if (!ui->actionRead_Only_Mode->isChecked())
                    ui->actionRead_Only_Mode->trigger();
            }

            return true; // the only early-exit in the loop
        }
        default:
            switch (qryptic.cipher().error()) {
            case Qrypto::IntegrityError:
                for (bool ok = true; ok; ok = false) {
                    const QString pwd = QInputDialog::getText(this, tr("Hash test failed"),
                                                              password->placeholderText(),
                                                              password->echoMode(),
                                                              password->text(), &ok);

                    if (ok && !pwd.isEmpty())
                        password->setText(pwd);
                    else
                        retry = false;
                }

                break;
            case Qrypto::OutOfMemory:
                retry = QMessageBox::critical(this, tr("Error"), tr("A resource error occurred."),
                                              QMessageBox::Retry | QMessageBox::Abort);
                break;
            case Qrypto::InvalidArgument:
                errorString = tr("Unsupported cryptographic parameters.");
                break;
            case Qrypto::InvalidFormat:
                errorString = tr("Invalid cryptographic format.");
                break;
            case Qrypto::NotImplemented:
                errorString = tr("Unknown cryptographic algorithm.");
                break;
            default:
                errorString = tr("An unspecified error occurred.");
            }

            if (!errorString.isEmpty())
                retry = QMessageBox::critical(this, tr("Error"), errorString);
        }
    }

    return false;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QSettings settings;
    settings.beginGroup("MainWindow");
    settings.setValue("Size", size());
    settings.setValue("State", saveState());
    QMainWindow::closeEvent(event);
}

void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);

    if (ui->textEdit->windowTitle().isEmpty()) {
        QSettings settings;
        ui->textEdit->setWindowTitle(tr("Untitled"));
        settings.beginGroup("MainWindow");
        resize(settings.value("Size", size()).toSize());
        restoreState(settings.value("State").toByteArray());
        clipboard_dataChanged();

        foreach (const QString &arg, qApp->arguments().mid(1))
            openFile(arg);
    }
}

void MainWindow::clipboard_dataChanged()
{
    const QMimeData *mime = qApp->clipboard()->mimeData();
    ui->actionPaste->setEnabled(mime && (mime->hasHtml() || mime->hasText()));
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
    QTextCharFormat fmt = ui->textEdit->currentCharFormat();

    if (checked) {
        fmt.setBackground(fmt.foreground().color());
        fmt.setForeground(Qt::transparent);
    } else {
        fmt.setForeground(Qt::NoBrush);
        fmt.setBackground(Qt::NoBrush);
    }

    ui->textEdit->setCurrentCharFormat(fmt);
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
    openFile(QFileDialog::getOpenFileName(this, trUtf8("Open File — %1").arg(qApp->applicationName())));
}

void MainWindow::on_actionQuit_triggered()
{
    close();
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
    const QString fileName = ui->textEdit->document()->metaInformation(QTextDocument::DocumentUrl);
    ui->textEdit->clear();
    openFile(fileName);
}

void MainWindow::on_actionSave_As_triggered()
{
    if (ui->passwordLineEdit->text().isEmpty()) {
        if (QMessageBox::question(this, trUtf8("Encryption Settings — %1").arg(qApp->applicationName()),
                                  tr("Enable encryption? You will need to set the password."),
                                  QMessageBox::Yes, QMessageBox::No) == QMessageBox::Yes) {
            ui->passwordLineEdit->setFocus();
            return;
        }
    }

    const QString fileName = QFileDialog::getSaveFileName(this, trUtf8("Save File — %1").arg(qApp->applicationName()));

    if (!fileName.isEmpty()) {
        ui->textEdit->document()->setMetaInformation(QTextDocument::DocumentUrl, fileName);
        on_actionSave_triggered();
    }
}

void MainWindow::on_actionSave_triggered()
{
    const QString fileName = ui->textEdit->document()->metaInformation(QTextDocument::DocumentUrl);

    if (fileName.isEmpty())
        on_actionSave_As_triggered();
    else {
        QSaveFile saveFile(fileName);
        QryptIO qryptic(&saveFile);
        QString pwd = ui->passwordLineEdit->text();

        if (pwd.isEmpty()) {
            pwd.clear();
        } else {
            qryptic.cipher().setAlgorithmName(ui->cipherComboBox->currentText());
            qryptic.cipher().setOperationCode(ui->methodComboBox->currentText());
        }

        for (int retry = QMessageBox::Retry; retry == QMessageBox::Retry; ) {
            switch (qryptic.write(ui->textEdit->toHtml().toUtf8(), pwd)) {
            case QryptIO::EncryptionFailed:
                retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                              tr("The document encryption scheme is not supported."),
                                              QMessageBox::Ok);
                break;
            case QryptIO::Ok:
                if (saveFile.commit()) {
                    const QFileInfo fileInfo(fileName);
                    QDir::setCurrent(fileInfo.dir().path());
                    ui->textEdit->document()->setMetaInformation(QTextDocument::DocumentUrl, fileInfo.filePath());
                    ui->textEdit->document()->setModified(false);
                    ui->textEdit->setWindowTitle(fileInfo.fileName());
                    return;
                }
            default:
                retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                              tr("The document could not be saved, as it was not possible to write to %1.")
                                              .arg(fileName), QMessageBox::Retry, QMessageBox::Abort);
                break;
            }
        }
    }
}

void MainWindow::on_actionText_Color_triggered()
{
    const QColor c = QColorDialog::getColor(ui->textEdit->textColor(), this,
                                            trUtf8("Select Color — %1").arg(qApp->applicationName()));

    if (c.isValid())
        ui->textEdit->setTextColor(c);
}

void MainWindow::on_actionText_Highlight_triggered()
{
    const QColor c = QColorDialog::getColor(ui->textEdit->textBackgroundColor(), this,
                                            trUtf8("Select Color — %1").arg(qApp->applicationName()));

    if (c.isValid())
        ui->textEdit->setTextBackgroundColor(c);
}

void MainWindow::on_actionWord_Wrap_triggered(bool checked)
{
    ui->textEdit->setWordWrapMode(QTextOption::WrapMode(checked));
}

void MainWindow::on_sizeComboBox_currentIndexChanged(int id)
{
    ui->textEdit->setFontPointSize(ui->sizeComboBox->itemData(id).toInt());
}

void MainWindow::on_textEdit_currentCharFormatChanged(const QTextCharFormat &format)
{
    ui->actionBold->setChecked(format.fontWeight() > 50);
    ui->actionCensor->setChecked(format.foreground().color().alpha() == 0);
    ui->actionItalic->setChecked(format.fontItalic());
    ui->actionUnderline->setChecked(format.fontUnderline());
    ui->fontComboBox->setCurrentFont(format.font());

    for (int i = 0, s = format.fontPointSize() + 0.5; i < ui->sizeComboBox->count(); ++i) {
        if (ui->sizeComboBox->itemData(i).toInt() == s) {
            ui->sizeComboBox->setCurrentIndex(i);
            return;
        }
    }

    ui->sizeComboBox->setCurrentText(locale().toString(format.fontPointSize()));
}

void MainWindow::on_textEdit_cursorPositionChanged()
{
    ui->statusBar->showMessage(tr("%1 : Line %2 : Column %3")
                               .arg(ui->textEdit->document()->metaInformation(QTextDocument::DocumentUrl))
                               .arg(ui->textEdit->textCursor().blockNumber() + 1)
                               .arg(ui->textEdit->textCursor().columnNumber() + 1));
}

void MainWindow::on_textEdit_windowTitleChanged()
{
    on_textEdit_cursorPositionChanged();
    setWindowTitle(trUtf8("%1%2 — %3")
                   .arg(ui->textEdit->windowTitle())
                   .arg(ui->textEdit->document()->isModified() ? "*" : "")
                   .arg(qApp->applicationName()));
}
