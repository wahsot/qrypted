/* Qrypto 2019
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

namespace Qrypto
{

/**
 * @brief The Compress class utilises the backend lossless data compression utilities
 */
class Compress
{
    struct Impl;
    friend struct Impl;

    QString m_algorithmName;

public:
    enum Algorithm {
        Bz2,
        Deflate,
        GZip,
        Identity,
        Lzma,
        ZLib,
        UnknownAlgorithm
    };

    static const QStringList AlgorithmNames;

    Compress(Algorithm algorithm = ZLib) :
        m_algorithmName(AlgorithmNames.at(algorithm))
    { }

    /**
     * @brief deflate data into compressed
     * @param deflated result
     * @param data to defalte
     * @param deflateLevel 0 to 9
     * @return deflation error
     */
    Error deflate(SequreBytes &deflated, const QByteArray &data, int deflateLevel = 6);

    /**
     * @brief inflate data from compressed
     * @param inflated result
     * @param data to inflate
     * @param repeat decompress multiple streams in series
     * @return inflation error
     */
    Error inflate(SequreBytes &inflated, const QByteArray &data, bool repeat = false);

    Algorithm algorithm() const
    {
        for (int i = AlgorithmNames.size(); i-- > 0; ) {
            if (AlgorithmNames.at(i).compare(m_algorithmName, Qt::CaseInsensitive) == 0)
                return Algorithm(i);
        }

        return UnknownAlgorithm;
    }

    void setAlgorithm(Algorithm algorithm)
    { m_algorithmName = AlgorithmNames.at(algorithm); }

    QString algorithmName() const
    { return m_algorithmName; }

    void setAlgorithmName(const QString &algorithmName)
    {
        if (AlgorithmNames.contains(algorithmName, Qt::CaseInsensitive))
            m_algorithmName = algorithmName;
        else
            m_algorithmName.clear();
    }
};

}

#endif // QRYPTO_COMPRESS_H
