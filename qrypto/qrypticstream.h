/* Qrypto 2016
**
** GNU Lesser General Public License Usage
** This file may be used under the terms of the GNU Lesser
** General Public License version 2.1 or version 3 as published by the Free
** Software Foundation and appearing in the file LICENSE.LGPLv21 and
** LICENSE.LGPLv3 included in the packaging of this file. Please review the
** following information to ensure the GNU Lesser General Public License
** requirements will be met: https://www.gnu.org/licenses/lgpl.html and
** http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**/
#ifndef QRYPTICSTREAM_H
#define QRYPTICSTREAM_H

#include "qrypto.h"

class QIODevice;

class QryptIO
{
    struct Private;
    Private *d;

public:
    /**
     * @brief The Status enum wanted to use QTextStream::Status, but it needed more statuses
     */
    enum Status {
        Ok,
        ReadPastEnd,        // unreadable device
        ReadCorruptData,    // malformed cryptic format
        WriteFailed,        // unwritable device
        KeyDerivationError,
        CryptographicError,
        CompressionError
    };

    QryptIO(QIODevice *device);

    ~QryptIO();

    /**
     * @brief decrypt data from underlying device
     * @param data
     * @param password
     * @return
     */
    Status decrypt(QByteArray &data, const QString &password);

    /**
     * @brief encrypt data into underlying device
     * @param data
     * @param password
     * @return
     */
    Status encrypt(const QByteArray &data, const QString &password);

    /**
     * @part 1: Preencryption Datacompression
     * @include qryptocompress.h
     * @brief compress manages the data compression algorithm
     * @return
     * @note using ZLib is best
     */
    Qrypto::Compress &compress();

    /**
     * @part 2: Passwordbased Keyderivation
     * @include qryptokeymaker.h
     * @brief keyMaker manages the key derivation algorithm
     * @return
     * @note also stores the key and HMAC functionality, that uses the key
     */
    Qrypto::KeyMaker &keyMaker();

    /**
     * @part 3: Encryption
     * @include qryptocipher.h
     * @brief cipher manages the block cipher algorithm
     * @return
     * @note also handles data authentication
     */
    Qrypto::Cipher &cipher();

    /**
     * @brief crypticVersion
     * @return < 0 for unknown, 0 for non-cryptic, > 0 for cryptic
     */
    int crypticVersion();

    QIODevice *device() const;

    /**
     * @brief error returns the last error
     * @return
     */
    Qrypto::Error error() const;

    Status status() const;

};

#endif // QRYPTICSTREAM_H
