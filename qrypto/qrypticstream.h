#ifndef QRYPTICSTREAM_H
#define QRYPTICSTREAM_H

#include "qrypto.h"

class QIODevice;

namespace Qrypto
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
        ReadPastEnd,        // unreadable device
        ReadCorruptData,    // malformed cryptic format
        WriteFailed,        // unwritable device
        DecryptionFailed,   // ask cipher.error
        EncryptionFailed    // ask cipher.error
    };

    QryptIO(QIODevice *device);

    ~QryptIO();

    /**
     * @brief crypticVersion
     * @return < 0 for unknown, 0 for non-cryptic, > 0 for cryptic
     */
    int crypticVersion();

    Qrypto::Error error() const;

    Status read(QByteArray &data, const QString &password);

    Status write(const QByteArray &data, const QString &password);

    Status status() const;

    Qrypto::Cipher &cipher();

    Qrypto::KeyMaker &keyMaker();

};

#endif // QRYPTICSTREAM_H
