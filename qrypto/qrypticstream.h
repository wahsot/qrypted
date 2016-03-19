#ifndef QRYPTICSTREAM_H
#define QRYPTICSTREAM_H

class QByteArray;
class QIODevice;
class QString;
class QXmlStreamReader;
class QXmlStreamWriter;

namespace QryptoPP
{
/// @header qryptocipher.h
class Cipher;

/// @header qryptokeymaker.h
class KeyMaker;
}

class QryptIO
{
    struct Private;
    Private *d;

public:
    enum Status {
        Ok,
        ReadPastEnd,
        ReadCorruptData,
        WriteFailed,
        DecryptionFailed,
        EncryptionFailed
    };

    QryptIO(QIODevice *device);

    ~QryptIO();

    int crypticVersion();

    Status read(QByteArray &data, const QString &password);

    Status write(const QByteArray &data, const QString &password);

    QryptoPP::Cipher &cipher();

    QryptoPP::KeyMaker &keyMaker();

};

#endif // QRYPTICSTREAM_H
