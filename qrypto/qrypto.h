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
**/
#ifndef QRYPTO_QRYPTO_H
#define QRYPTO_QRYPTO_H

#include <QStringList>
#include <vector>

namespace Qrypto
{

enum Error {
    NoError,
    NotImplemented,
    InvalidArgument,
    IntegrityError,
    InvalidFormat,
    OutOfMemory,
    UnknownError,
};

/// @include qryptocipher.h
class Cipher;

/// @include qrypticompress.h
class Compress;

/// @include qryptokeymaker.h
class KeyMaker;

/// @include sequre.h
template <class Str, typename Len, typename Chr>
class Sequre;

typedef Sequre<QByteArray, int, char> SequreBytes;
typedef Sequre<QString, int, QChar> SequreString;
typedef Sequre<std::string, size_t, char> SequreStr;
typedef Sequre<std::vector<uchar>, size_t, uchar> SequreData;

}

#endif // QRYPTO_QRYPTO_H
