#include "../qryptocompress.h"

#include "../sequre.h"

#include <QScopedPointer>

#include <cryptopp/gzip.h>
#include <cryptopp/zlib.h>

namespace Qrypto
{
typedef CryptoPP::StringSinkTemplate<SequreBytes> SequreSink;
}

using namespace Qrypto;

const QStringList Compress::AlgorithmNames =
        QStringList() << QString() <<
                         "Deflate" <<
                         "GZip" <<
                         "Identity" <<
                         QString() <<
                         "ZLib" <<
                         QString();

Error Compress::deflate(SequreBytes &deflated, const QByteArray &data, int deflateLevel)
{
    QScopedPointer<CryptoPP::Deflator> deflator;
    deflateLevel = qBound(0, deflateLevel, 9);

    switch (algorithm()) {
    case Identity:
        deflated.assign(data);
        return NoError;
    case Deflate:
        deflator.reset(new CryptoPP::Deflator(new SequreSink(deflated), deflateLevel));
        break;
    case GZip:
        deflator.reset(new CryptoPP::Gzip(new SequreSink(deflated), deflateLevel));
        break;
    case ZLib:
        deflator.reset(new CryptoPP::ZlibCompressor(new SequreSink(deflated), deflateLevel));
        break;
    default:
        return NotImplemented;
    }

    try {
        deflated.reserve(data.size());
        deflated.resize(0);
        CryptoPP::StringSource(reinterpret_cast<const CryptoPP::byte*>(data.constData()), data.size(),
                               true, deflator.take());
        return NoError;
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        return UnknownError;
    }
}

Error Compress::inflate(SequreBytes &inflated, const QByteArray &data, bool repeat)
{
    QScopedPointer<CryptoPP::Inflator> inflator;

    switch (algorithm()) {
    case Identity:
        inflated.assign(data);
        return NoError;
    case Deflate:
        inflator.reset(new CryptoPP::Inflator(new SequreSink(inflated), repeat));
        break;
    case GZip:
        inflator.reset(new CryptoPP::Gunzip(new SequreSink(inflated), repeat));
        break;
    case ZLib:
        inflator.reset(new CryptoPP::ZlibDecompressor(new SequreSink(inflated), repeat));
        break;
    default:
        return NotImplemented;
    }

    try {
        inflated.reserve(data.size());
        inflated.resize(0);
        CryptoPP::StringSource(reinterpret_cast<const CryptoPP::byte*>(data.constData()), data.size(),
                               true, inflator.take());
        return NoError;
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::INVALID_DATA_FORMAT:
            return InvalidFormat;
        case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED:
            return IntegrityError;
        default:
            qCritical(exc.what());
            return UnknownError;
        }
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        return UnknownError;
    }
}
