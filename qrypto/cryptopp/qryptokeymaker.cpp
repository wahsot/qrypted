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

struct KeyMaker::Private
{
    KeyMaker::Algorithm algorithm;
    CryptoPP::SecByteBlock key;
    QByteArray salt;
    uint iteration;
    uint iterationTime;

    Private(KeyMaker::Algorithm algorithm, uint keyLength) :
        algorithm(algorithm),
        key(keyLength),
        iteration(100000),
        iterationTime(0)
    { }

    CryptoPP::MessageAuthenticationCode *getHMAC()
    {
        if (key.empty())
            return 0;

        switch (algorithm) {
        case KeyMaker::RipeMD_160:
            return new CryptoPP::HMAC<CryptoPP::RIPEMD160>(key.data(), key.size());
        case KeyMaker::RipeMD_320:
            return new CryptoPP::HMAC<CryptoPP::RIPEMD320>(key.data(), key.size());
        case KeyMaker::Sha1:
            return new CryptoPP::HMAC<CryptoPP::SHA1>(key.data(), key.size());
        case KeyMaker::Sha224:
            return new CryptoPP::HMAC<CryptoPP::SHA224>(key.data(), key.size());
        case KeyMaker::Sha256:
            return new CryptoPP::HMAC<CryptoPP::SHA256>(key.data(), key.size());
        case KeyMaker::Sha384:
            return new CryptoPP::HMAC<CryptoPP::SHA384>(key.data(), key.size());
        case KeyMaker::Sha512:
            return new CryptoPP::HMAC<CryptoPP::SHA512>(key.data(), key.size());
        case KeyMaker::Sha3_224:
            return new CryptoPP::HMAC<CryptoPP::SHA3_224>(key.data(), key.size());
        case KeyMaker::Sha3_256:
            return new CryptoPP::HMAC<CryptoPP::SHA3_256>(key.data(), key.size());
        case KeyMaker::Sha3_384:
            return new CryptoPP::HMAC<CryptoPP::SHA3_384>(key.data(), key.size());
        case KeyMaker::Sha3_512:
            return new CryptoPP::HMAC<CryptoPP::SHA3_512>(key.data(), key.size());
        case KeyMaker::Tiger:
            return new CryptoPP::HMAC<CryptoPP::Tiger>(key.data(), key.size());
        case KeyMaker::Whirlpool:
            return new CryptoPP::HMAC<CryptoPP::Whirlpool>(key.data(), key.size());
        default:
            return 0;
        }
    }

    template <class Alg>
    Error deriveKey(const char *pwData, uint pwSize, size_t keyLength)
    {
        CryptoPP::PKCS5_PBKDF2_HMAC<Alg> PBKDF;

        try {
            key.resize(std::min(keyLength, PBKDF.MaxDerivedKeyLength()));

            if (salt.isEmpty())
                salt.fill('\0', Alg::DIGESTSIZE / 2); // using resize seems to optimise out the count

            if (salt.count('\0') == salt.size()) {
                CryptoPP::AutoSeededRandomPool prng;

                for (int zeroes = salt.size(), half = zeroes / 2; zeroes > half; zeroes = salt.count('\0'))
                    prng.GenerateBlock(reinterpret_cast<byte*>(salt.data()), salt.size());
            }

            iteration = PBKDF.DeriveKey(key.data(), key.size(), 0,
                                        reinterpret_cast<const byte*>(pwData), pwSize,
                                        reinterpret_cast<const byte*>(salt.constData()), salt.size(),
                                        iteration, iterationTime / 1000.0);

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

KeyMaker::KeyMaker(Algorithm algorithm, uint keyLength) :
    d(new Private(algorithm, keyLength))
{ }

KeyMaker::KeyMaker(const KeyMaker &keyMaker) :
    d(new Private(*keyMaker.d))
{ }

KeyMaker::KeyMaker(const QString &algorithmName, uint keyLength) :
    d(new Private(UnknownAlgorithm, keyLength))
{
    setAlgorithmName(algorithmName);
}

KeyMaker::~KeyMaker()
{
    delete d;
}

KeyMaker &KeyMaker::operator=(const KeyMaker &keyMaker)
{
    *d = *keyMaker.d;
    return *this;
}

KeyMaker::Algorithm KeyMaker::algorithm() const
{
    return d->algorithm;
}

QString KeyMaker::algorithmName() const
{
    return AlgorithmNames.at(d->algorithm);
}

QByteArray KeyMaker::authenticate(const char *messageData, uint messageSize, uint truncatedSize) const
{
    QScopedPointer<CryptoPP::MessageAuthenticationCode> HMAC(d->getHMAC());
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
        keyLength = d->key.size();

    if (!keyLength)
        return InvalidArgument;

    switch (d->algorithm) {
    case RipeMD_160:
        return d->deriveKey<CryptoPP::RIPEMD160>(passwordData, passwordSize, keyLength);
    case RipeMD_320:
        return d->deriveKey<CryptoPP::RIPEMD320>(passwordData, passwordSize, keyLength);
    case Sha1:
        return d->deriveKey<CryptoPP::SHA1>(passwordData, passwordSize, keyLength);
    case Sha224:
        return d->deriveKey<CryptoPP::SHA224>(passwordData, passwordSize, keyLength);
    case Sha256:
        return d->deriveKey<CryptoPP::SHA256>(passwordData, passwordSize, keyLength);
    case Sha384:
        return d->deriveKey<CryptoPP::SHA384>(passwordData, passwordSize, keyLength);
    case Sha512:
        return d->deriveKey<CryptoPP::SHA512>(passwordData, passwordSize, keyLength);
    case Sha3_224:
        return d->deriveKey<CryptoPP::SHA3_224>(passwordData, passwordSize, keyLength);
    case Sha3_256:
        return d->deriveKey<CryptoPP::SHA3_256>(passwordData, passwordSize, keyLength);
    case Sha3_384:
        return d->deriveKey<CryptoPP::SHA3_384>(passwordData, passwordSize, keyLength);
    case Sha3_512:
        return d->deriveKey<CryptoPP::SHA3_512>(passwordData, passwordSize, keyLength);
    case Tiger:
        return d->deriveKey<CryptoPP::Tiger>(passwordData, passwordSize, keyLength);
    case Whirlpool:
        return d->deriveKey<CryptoPP::Whirlpool>(passwordData, passwordSize, keyLength);
    default:
        return NotImplemented;
    }
}

uint KeyMaker::iterationCount() const
{
    return d->iteration;
}

uint KeyMaker::iterationTime() const
{
    return d->iterationTime;
}

const uchar *KeyMaker::keyData() const
{
    return d->key.data();
}

uint KeyMaker::keyLength() const
{
    return d->key.size();
}

QByteArray KeyMaker::salt() const
{
    return d->salt;
}

void KeyMaker::setAlgorithm(Algorithm algorithm)
{
    d->algorithm = algorithm;
}

void KeyMaker::setAlgorithmName(const QString &algorithmName)
{
    for (int i = UnknownAlgorithm; i-- > 0; ) {
        if (AlgorithmNames.at(i).compare(algorithmName, Qt::CaseInsensitive) == 0) {
            d->algorithm = Algorithm(i);
            return;
        }
    }

    d->algorithm = UnknownAlgorithm;
}

void KeyMaker::setIterationCount(uint iterationCount)
{
    d->iteration = iterationCount;
}

void KeyMaker::setIterationTime(uint milliseconds)
{
    d->iterationTime = milliseconds;
}

void KeyMaker::setKeyLength(uint keyLength)
{
    d->key.resize(keyLength);
}

void KeyMaker::setSalt(const QByteArray &salt)
{
    d->salt = salt;
}
