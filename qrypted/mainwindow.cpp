#include "mainwindow.h"
#include "ui_mainwindow.h"

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
#include <QTextCodec>
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

    for (int i = 0, l = QrypticStream::Ciphers.size() - 1; i < l; ++i)
        ui->cipherComboBox->addItem(QrypticStream::Ciphers.at(i), i);

    for (int i = 0, l = QrypticStream::Digests.size() - 1; i < l; ++i)
        ui->digestComboBox->addItem(QrypticStream::Digests.at(i), i);

    for (int i = 0, l = QrypticStream::Methods.size() - 1; i < l; ++i)
        ui->methodComboBox->addItem(QrypticStream::Methods.at(i), i);

    setWindowTitle(qApp->applicationName());
    ui->actionAbout->setText(ui->actionAbout->text().arg(qApp->applicationName()));
    ui->sizeComboBox->setCurrentIndex(6);
    ui->formatToolBar->insertWidget(ui->actionBold, ui->fontComboBox);
    ui->formatToolBar->insertWidget(ui->actionBold, ui->sizeComboBox);
    ui->formatToolBar->insertSeparator(ui->actionBold);
    ui->cipherComboBox->setCurrentIndex(3);
    ui->digestComboBox->setCurrentIndex(1);
    ui->methodComboBox->setCurrentIndex(1);
    ui->mainToolBar->addWidget(ui->passwordLineEdit);
    ui->mainToolBar->addWidget(ui->cipherComboBox);
    ui->mainToolBar->addWidget(ui->digestComboBox);
    ui->mainToolBar->addWidget(ui->methodComboBox);
    ui->searchToolBar->insertWidget(ui->actionFind_Previous, ui->findLineEdit);
    ui->searchToolBar->insertSeparator(ui->actionFind_Previous);
    ui->searchToolBar->hide();
    ui->textEdit->setFontFamily("monospace");
    ui->textEdit->setFontPointSize(12);
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
    connect(ui->textEdit->document(), SIGNAL(modificationChanged(bool)),
            this, SLOT(document_modificationChanged(bool)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::openFile(const QString &fileName)
{
    if (fileName.isEmpty())
        return false;
    else if (ui->textEdit->document()->isEmpty()) {
        QFile f(fileName);

        for (int retry = QMessageBox::Retry; retry == QMessageBox::Retry; ) {
            if (f.open(QFile::ReadOnly)) {
                QTextStream stream(&f);
                ui->textEdit->setText(stream.readAll());
                f.close();

                if (stream.status() == QTextStream::Ok) {
                    const QFileInfo fileInfo(fileName);
                    QDir::setCurrent(fileInfo.dir().path());
                    ui->textEdit->document()->setMetaInformation(QTextDocument::DocumentUrl, fileInfo.filePath());
                    ui->textEdit->setDocumentTitle(fileInfo.fileName());
                    setWindowTitle(trUtf8("%1 — %2").arg(fileInfo.fileName()).arg(qApp->applicationName()));

                    if (ui->actionRead_Only_Mode->isChecked())
                        ui->actionRead_Only_Mode->trigger();

                    return true;
                } else {
                    retry = QMessageBox::warning(this, trUtf8("Warning — %1").arg(qApp->applicationName()),
                                                 tr("The file %1 was opened with %2 encoding but contained invalid characters.")
                                                 .arg(fileName), QMessageBox::Retry, QMessageBox::Close);

                    if (retry == QMessageBox::Close && !ui->actionRead_Only_Mode->isChecked())
                        ui->actionRead_Only_Mode->trigger();
                }
            } else {
                retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                              tr("The file %1 could not be loaded, as it was not possible to read from it.")
                                              .arg(fileName), QMessageBox::Retry, QMessageBox::Close);
            }
        }
    } else
        return QProcess::startDetached(qApp->applicationFilePath(), QStringList() << fileName);

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
    if (ui->textEdit->documentTitle().isEmpty()) {
        QSettings settings;

        foreach (const QString &arg, qApp->arguments().mid(1))
            openFile(arg);

        ui->textEdit->setDocumentTitle(tr("Untitled"));
        settings.beginGroup("MainWindow");
        resize(settings.value("Size", size()).toSize());
        restoreState(settings.value("State").toByteArray());
        clipboard_dataChanged();
        document_modificationChanged(false);
    }

    QMainWindow::showEvent(event);
}

void MainWindow::clipboard_dataChanged()
{
    const QMimeData *mime = qApp->clipboard()->mimeData();
    ui->actionPaste->setEnabled(mime && (mime->hasHtml() || mime->hasText()));
}

void MainWindow::document_modificationChanged(bool modified)
{
    setWindowTitle(trUtf8("%1%2 — %3")
                   .arg(ui->textEdit->documentTitle())
                   .arg(modified ? "*" : "")
                   .arg(qApp->applicationName()));
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
    QTextCharFormat textFormat = ui->textEdit->currentCharFormat();

    if (checked) {
        textFormat.setBackground(textFormat.foreground());
        textFormat.setForeground(Qt::transparent);
    } else {
        textFormat.setForeground(textFormat.background());
        textFormat.clearBackground();
    }

    ui->textEdit->setCurrentCharFormat(textFormat);
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
        QByteArray data = ui->textEdit->toHtml().toUtf8();
        QSaveFile f(fileName);

        if (!ui->passwordLineEdit->text().isEmpty()) {
            QBuffer buffer;
            QrypticStream stream(&buffer);
            stream.setSettings(QrypticStream::Settings(QrypticStream::Cipher(ui->cipherComboBox->currentData().toInt()),
                                                       QrypticStream::Method(ui->methodComboBox->currentData().toInt()),
                                                       QrypticStream::Digest(ui->digestComboBox->currentData().toInt())));

            if (stream.encrypt(data))
                buffer.buffer().swap(data);
        }

        for (int retry = QMessageBox::Retry; retry == QMessageBox::Retry; ) {
            if (f.open(QFile::WriteOnly) && f.write(data) == data.size() && f.commit()) {
                const QFileInfo fileInfo(fileName);
                QDir::setCurrent(fileInfo.dir().path());
                ui->textEdit->document()->setMetaInformation(QTextDocument::DocumentUrl, fileInfo.filePath());
                ui->textEdit->setDocumentTitle(fileInfo.fileName());
                setWindowTitle(trUtf8("%1 — %2").arg(fileInfo.fileName()).arg(qApp->applicationName()));
                return;
            } else {
                retry = QMessageBox::critical(this, trUtf8("Error — %1").arg(qApp->applicationName()),
                                              tr("The document could not be saved, as it was not possible to write to %1.")
                                              .arg(fileName), QMessageBox::Retry, QMessageBox::Abort);
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
