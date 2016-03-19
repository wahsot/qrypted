#include "qryptokeymaker.h"

#include <cryptopp/cryptlib.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/whrlpool.h>

namespace QryptoPP
{

struct KeyMaker::Private
{
    KeyMaker::Algorithm algorithm;
    QByteArray salt;
    uint iteration;

    Private(KeyMaker::Algorithm algorithm, uint iteration) :
        algorithm(algorithm),
        iteration(iteration)
    { }

    template <class Alg>
    size_t deriveKey(void *data, size_t dkLen, const QByteArray &pwd)
    {
        typename CryptoPP::PKCS5_PBKDF2_HMAC<Alg> PBKDF;
        dkLen = std::min(PBKDF.MaxDerivedKeyLength(), dkLen);

        try {
            if (salt.isEmpty()) {
                CryptoPP::AutoSeededRandomPool prng;
                salt.resize(Alg::DIGESTSIZE);
                prng.GenerateBlock(reinterpret_cast<byte*>(salt.data()), salt.size());
            }

            PBKDF.DeriveKey(reinterpret_cast<byte*>(data), dkLen, 0,
                            reinterpret_cast<const byte*>(pwd.constData()), pwd.size(),
                            reinterpret_cast<const byte*>(salt.constData()), salt.size(),
                            iteration);
            return dkLen;
        } catch (...) {
            return 0;
        }
    }
};

}

using namespace QryptoPP;

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

uint KeyMaker::deriveKey(void *keyData, uint desiredKeyLength, const QByteArray &password)
{
    switch (d->algorithm) {
    case RipeMD_160:
        return d->deriveKey<CryptoPP::RIPEMD160>(keyData, desiredKeyLength, password);
    case RipeMD_320:
        return d->deriveKey<CryptoPP::RIPEMD320>(keyData, desiredKeyLength, password);
    case Sha1:
        return d->deriveKey<CryptoPP::SHA1>(keyData, desiredKeyLength, password);
    case Sha224:
        return d->deriveKey<CryptoPP::SHA224>(keyData, desiredKeyLength, password);
    case Sha256:
        return d->deriveKey<CryptoPP::SHA256>(keyData, desiredKeyLength, password);
    case Sha384:
        return d->deriveKey<CryptoPP::SHA384>(keyData, desiredKeyLength, password);
    case Sha512:
        return d->deriveKey<CryptoPP::SHA512>(keyData, desiredKeyLength, password);
    case Sha3_224:
        return d->deriveKey<CryptoPP::SHA3_224>(keyData, desiredKeyLength, password);
    case Sha3_256:
        return d->deriveKey<CryptoPP::SHA3_256>(keyData, desiredKeyLength, password);
    case Sha3_384:
        return d->deriveKey<CryptoPP::SHA3_384>(keyData, desiredKeyLength, password);
    case Sha3_512:
        return d->deriveKey<CryptoPP::SHA3_512>(keyData, desiredKeyLength, password);
    case Whirlpool:
        return d->deriveKey<CryptoPP::Whirlpool>(keyData, desiredKeyLength, password);
    default:
        return 0;
    }
}

uint KeyMaker::iterationCount() const
{
    return d->iteration;
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
