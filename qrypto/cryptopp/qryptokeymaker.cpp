#include "../qryptokeymaker.h"

#include <QScopedPointer>

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/tiger.h>
#include <cryptopp/whrlpool.h>

namespace Qrypto
{

struct KeyMaker::Impl
{
    KeyMaker *q;

    Impl(KeyMaker *q = 0) : q(q) { }

    static CryptoPP::MessageAuthenticationCode *getHMAC(const KeyMaker *p)
    {
        if (!p->keyLength())
            return 0;

        switch (p->algorithm()) {
        case KeyMaker::RipeMD_160:
            return new CryptoPP::HMAC<CryptoPP::RIPEMD160>(p->keyData(), p->keyLength());
        case KeyMaker::RipeMD_320:
            return new CryptoPP::HMAC<CryptoPP::RIPEMD320>(p->keyData(), p->keyLength());
        case KeyMaker::Sha1:
            return new CryptoPP::HMAC<CryptoPP::SHA1>(p->keyData(), p->keyLength());
        case KeyMaker::Sha224:
            return new CryptoPP::HMAC<CryptoPP::SHA224>(p->keyData(), p->keyLength());
        case KeyMaker::Sha256:
            return new CryptoPP::HMAC<CryptoPP::SHA256>(p->keyData(), p->keyLength());
        case KeyMaker::Sha384:
            return new CryptoPP::HMAC<CryptoPP::SHA384>(p->keyData(), p->keyLength());
        case KeyMaker::Sha512:
            return new CryptoPP::HMAC<CryptoPP::SHA512>(p->keyData(), p->keyLength());
        case KeyMaker::Sha3_224:
            return new CryptoPP::HMAC<CryptoPP::SHA3_224>(p->keyData(), p->keyLength());
        case KeyMaker::Sha3_256:
            return new CryptoPP::HMAC<CryptoPP::SHA3_256>(p->keyData(), p->keyLength());
        case KeyMaker::Sha3_384:
            return new CryptoPP::HMAC<CryptoPP::SHA3_384>(p->keyData(), p->keyLength());
        case KeyMaker::Sha3_512:
            return new CryptoPP::HMAC<CryptoPP::SHA3_512>(p->keyData(), p->keyLength());
        case KeyMaker::Tiger:
            return new CryptoPP::HMAC<CryptoPP::Tiger>(p->keyData(), p->keyLength());
        case KeyMaker::Whirlpool:
            return new CryptoPP::HMAC<CryptoPP::Whirlpool>(p->keyData(), p->keyLength());
        default:
            return 0;
        }
    }

    template <class Alg>
    Error deriveKey(const char *pwData, uint pwSize, size_t keyLength) const
    {
        CryptoPP::PKCS5_PBKDF2_HMAC<Alg> PBKDF;

        try {
            q->m_key.resize(std::min(keyLength, PBKDF.MaxDerivedKeyLength()));

            if (q->m_salt.isEmpty())
                q->m_salt.fill('\0', Alg::DIGESTSIZE / 2); // using resize seems to optimise out the count

            if (q->m_salt.count('\0') == q->m_salt.size()) {
                CryptoPP::AutoSeededRandomPool prng;

                for (int zeroes = q->m_salt.size(), half = zeroes / 2; zeroes > half; zeroes = q->m_salt.count('\0'))
                    prng.GenerateBlock(reinterpret_cast<byte*>(q->m_salt.data()), q->m_salt.size());
            }

            q->m_iteration = PBKDF.DeriveKey(q->m_key->data(), q->m_key->size(), 0,
                                             reinterpret_cast<const byte*>(pwData), pwSize,
                                             reinterpret_cast<const byte*>(q->m_salt.constData()), q->m_salt.size(),
                                             q->m_iteration, q->m_iterationTime / 1000.0);

            return NoError;
        } catch (const std::bad_alloc &exc) {
            return OutOfMemory;
        } catch (const CryptoPP::Exception &exc) {
            qCritical(exc.what());

            switch (exc.GetErrorType()) {
            case CryptoPP::Exception::INVALID_ARGUMENT:
                return InvalidArgument;
            default:
                return UnknownError;
            }
        }
    }
};

}

using namespace Qrypto;

const QStringList KeyMaker::AlgorithmNames =
        QStringList() << CryptoPP::RIPEMD160::StaticAlgorithmName() <<
                         CryptoPP::RIPEMD320::StaticAlgorithmName() <<
                         CryptoPP::SHA1::StaticAlgorithmName() <<
                         CryptoPP::SHA224::StaticAlgorithmName() <<
                         CryptoPP::SHA256::StaticAlgorithmName() <<
                         CryptoPP::SHA384::StaticAlgorithmName() <<
                         CryptoPP::SHA512::StaticAlgorithmName() <<
                         CryptoPP::SHA3_224::StaticAlgorithmName() <<
                         CryptoPP::SHA3_256::StaticAlgorithmName() <<
                         CryptoPP::SHA3_384::StaticAlgorithmName() <<
                         CryptoPP::SHA3_512::StaticAlgorithmName() <<
                         CryptoPP::Tiger::StaticAlgorithmName() <<
                         CryptoPP::Whirlpool::StaticAlgorithmName() <<
                         QString();

QByteArray KeyMaker::authenticate(const char *messageData, uint messageSize, uint truncatedSize) const
{
    QScopedPointer<CryptoPP::MessageAuthenticationCode> HMAC(Impl::getHMAC(this));
    QByteArray code;

    if (HMAC) {
        if (0 < truncatedSize && truncatedSize < HMAC->DigestSize())
            HMAC->CalculateTruncatedDigest(reinterpret_cast<byte*>(code.fill(0, truncatedSize).data()),
                                           truncatedSize, reinterpret_cast<const byte*>(messageData),
                                           messageSize);
        else
            HMAC->CalculateDigest(reinterpret_cast<byte*>(code.fill(0, HMAC->DigestSize()).data()),
                                  reinterpret_cast<const byte*>(messageData), messageSize);
    }

    return code;
}

Error KeyMaker::deriveKey(const char *passwordData, uint passwordSize, uint keyLength)
{
    if (!passwordData || !passwordSize)
        return IntegrityError;

    if (!keyLength)
        keyLength = m_key->size();

    if (!keyLength)
        return InvalidArgument;

    const Impl f(this);

    switch (algorithm()) {
    case RipeMD_160:
        return f.deriveKey<CryptoPP::RIPEMD160>(passwordData, passwordSize, keyLength);
    case RipeMD_320:
        return f.deriveKey<CryptoPP::RIPEMD320>(passwordData, passwordSize, keyLength);
    case Sha1:
        return f.deriveKey<CryptoPP::SHA1>(passwordData, passwordSize, keyLength);
    case Sha224:
        return f.deriveKey<CryptoPP::SHA224>(passwordData, passwordSize, keyLength);
    case Sha256:
        return f.deriveKey<CryptoPP::SHA256>(passwordData, passwordSize, keyLength);
    case Sha384:
        return f.deriveKey<CryptoPP::SHA384>(passwordData, passwordSize, keyLength);
    case Sha512:
        return f.deriveKey<CryptoPP::SHA512>(passwordData, passwordSize, keyLength);
    case Sha3_224:
        return f.deriveKey<CryptoPP::SHA3_224>(passwordData, passwordSize, keyLength);
    case Sha3_256:
        return f.deriveKey<CryptoPP::SHA3_256>(passwordData, passwordSize, keyLength);
    case Sha3_384:
        return f.deriveKey<CryptoPP::SHA3_384>(passwordData, passwordSize, keyLength);
    case Sha3_512:
        return f.deriveKey<CryptoPP::SHA3_512>(passwordData, passwordSize, keyLength);
    case Tiger:
        return f.deriveKey<CryptoPP::Tiger>(passwordData, passwordSize, keyLength);
    case Whirlpool:
        return f.deriveKey<CryptoPP::Whirlpool>(passwordData, passwordSize, keyLength);
    default:
        return NotImplemented;
    }
}
