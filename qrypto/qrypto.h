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
#ifndef QRYPTO_QRYPTO_H
#define QRYPTO_QRYPTO_H

#include <QStringList>

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
class SequreStr;
class SequreBytes;
class SequreString;

}

#endif // QRYPTO_QRYPTO_H
