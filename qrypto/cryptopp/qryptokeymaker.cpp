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
    uint iteration;
    CryptoPP::SecByteBlock key;
    QByteArray salt;

    Private(KeyMaker::Algorithm algorithm, uint iteration) :
        algorithm(algorithm),
        iteration(iteration)
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
    size_t deriveKey(size_t dkLen, const QByteArray &pwd, uint ms)
    {
        CryptoPP::PKCS5_PBKDF2_HMAC<Alg> PBKDF;

        if (salt.isEmpty()) {
            salt.resize(Alg::DIGESTSIZE);
            CryptoPP::AutoSeededRandomPool().GenerateBlock(reinterpret_cast<byte*>(salt.data()),
                                                           salt.size());
        }

        key.resize(std::min(PBKDF.MaxDerivedKeyLength(), dkLen));
        iteration = PBKDF.DeriveKey(key.data(), key.size(), 0,
                                    reinterpret_cast<const byte*>(pwd.constData()), pwd.size(),
                                    reinterpret_cast<const byte*>(salt.constData()), salt.size(),
                                    iteration, ms / 1000.0);

        return key.size();
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

KeyMaker::KeyMaker(Algorithm algorithm, uint iterationCount) :
    d(new Private(algorithm, iterationCount))
{ }

KeyMaker::KeyMaker(const KeyMaker &keyMaker) :
    d(new Private(*keyMaker.d))
{ }

KeyMaker::KeyMaker(const QString &algorithmName, uint iterationCount) :
    d(new Private(UnknownAlgorithm, iterationCount))
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

QByteArray KeyMaker::authenticate(const char *messageData, uint messageSize)
{
    QScopedPointer<CryptoPP::MessageAuthenticationCode> HMAC(d->getHMAC());
    QByteArray code;

    if (HMAC) {
        HMAC->CalculateDigest(reinterpret_cast<byte*>(code.fill(0, HMAC->DigestSize()).data()),
                              reinterpret_cast<const byte*>(messageData), messageSize);
    }

    return code;
}

uint KeyMaker::deriveKey(const QByteArray &password, uint keyLength, uint milliseconds)
{
    switch (d->algorithm) {
    case RipeMD_160:
        return d->deriveKey<CryptoPP::RIPEMD160>(keyLength, password, milliseconds);
    case RipeMD_320:
        return d->deriveKey<CryptoPP::RIPEMD320>(keyLength, password, milliseconds);
    case Sha1:
        return d->deriveKey<CryptoPP::SHA1>(keyLength, password, milliseconds);
    case Sha224:
        return d->deriveKey<CryptoPP::SHA224>(keyLength, password, milliseconds);
    case Sha256:
        return d->deriveKey<CryptoPP::SHA256>(keyLength, password, milliseconds);
    case Sha384:
        return d->deriveKey<CryptoPP::SHA384>(keyLength, password, milliseconds);
    case Sha512:
        return d->deriveKey<CryptoPP::SHA512>(keyLength, password, milliseconds);
    case Sha3_224:
        return d->deriveKey<CryptoPP::SHA3_224>(keyLength, password, milliseconds);
    case Sha3_256:
        return d->deriveKey<CryptoPP::SHA3_256>(keyLength, password, milliseconds);
    case Sha3_384:
        return d->deriveKey<CryptoPP::SHA3_384>(keyLength, password, milliseconds);
    case Sha3_512:
        return d->deriveKey<CryptoPP::SHA3_512>(keyLength, password, milliseconds);
    case Tiger:
        return d->deriveKey<CryptoPP::Tiger>(keyLength, password, milliseconds);
    case Whirlpool:
        return d->deriveKey<CryptoPP::Whirlpool>(keyLength, password, milliseconds);
    default:
        return 0;
    }
}

uint KeyMaker::iterationCount() const
{
    return d->iteration;
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

void KeyMaker::setSalt(const QByteArray &salt)
{
    d->salt = salt;
}
