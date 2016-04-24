#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

class QFileDevice;
class QTextCharFormat;
class QTranslator;

class QryptIO;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

    QMenu *m_editMenu;

public:
    static QMultiMap<QString, QTranslator*> getTranslators();

    explicit MainWindow(QWidget *parent = 0);

    ~MainWindow();

    QString getErrorString(const QFileDevice &fileDevice) const;

    QString getErrorString(const QryptIO &qryptic) const;

    bool openFile(const QString &fileName);

    bool saveFile(const QString &fileName);

protected:
    void closeEvent(QCloseEvent *event);

    void showEvent(QShowEvent *event);

private slots:
    void on_actionAbout_Qt_triggered();

    void on_actionAbout_triggered();

    void on_actionAlign_Center_triggered(bool checked);

    void on_actionAlign_Left_triggered(bool checked);

    void on_actionAlign_Right_triggered(bool checked);

    void on_actionBold_triggered(bool checked);

    void on_actionCensor_triggered(bool checked);

    void on_actionFind_Next_triggered();

    void on_actionFind_Previous_triggered();

    void on_actionFind_triggered(bool checked);

    void on_actionNew_triggered();

    void on_actionOpen_triggered();

    void on_actionOverwrite_Mode_triggered(bool checked);

    void on_actionRead_Only_Mode_triggered(bool checked);

    void on_actionReload_triggered();

    void on_actionSave_As_triggered();

    void on_actionSave_triggered();

    void on_actionSwitch_Application_Language_triggered();

    void on_actionText_Color_triggered();

    void on_actionText_Highlight_triggered();

    void on_actionWord_Wrap_triggered(bool checked);

    void on_fontSpinBox_valueChanged(int value);

    void on_textEdit_currentCharFormatChanged(const QTextCharFormat &format);

    void on_textEdit_cursorPositionChanged();

    void on_textEdit_windowTitleChanged();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
