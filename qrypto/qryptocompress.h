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
**
** Botan 1.11 is licensed under Simplified BSD License
** CryptoPP 5.6.2 is licensed under Boost Software License 1.0
**/
#ifndef QRYPTO_COMPRESS_H
#define QRYPTO_COMPRESS_H

#include "qrypto.h"

#include <QStringList>

namespace Qrypto
{

/**
 * @brief The Compress class utilises the backend lossless data compression utilities
 */
struct Compress
{
    enum Algorithm {
        Identity,
        Deflate,
        GZip,
        ZLib,
        UnknownAlgorithm
    };

    static const QStringList AlgorithmNames;

    Algorithm algorithm;

    Compress(Algorithm algorithm = Identity) : algorithm(algorithm) { }

    Compress(const QString &algorithmName)
    { setAlgorithmName(algorithmName); }

    /**
     * @brief deflate data into compressed
     * @param compressed
     * @param data
     * @param deflateLevel 0 to 9
     * @return deflation error
     */
    Error deflate(QByteArray &compressed, const QByteArray &data, int deflateLevel = 6);

    /**
     * @brief inflate data from compressed
     * @param data
     * @param compressed
     * @param repeat decompress multiple streams in series
     * @return inflation error
     */
    Error inflate(QByteArray &data, const QByteArray &compressed, bool repeat = false);

    QString algorithmName() const
    { return AlgorithmNames.at(algorithm); }

    void setAlgorithmName(const QString &algorithmName)
    {
        for (int i = UnknownAlgorithm; i-- > 0; ) {
            if (AlgorithmNames.at(i).compare(algorithmName, Qt::CaseInsensitive) == 0) {
                algorithm = Algorithm(i);
                return;
            }
        }

        algorithm = UnknownAlgorithm;
    }
};

}

#endif // QRYPTO_COMPRESS_H
