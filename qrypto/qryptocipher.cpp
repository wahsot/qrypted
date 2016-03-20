#include "qryptocipher.h"

#include "qryptokeymaker.h"

#include <QVariant>

#include <cryptopp/camellia.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include <cryptopp/idea.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblock.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>

namespace QryptoPP
{

struct Cipher::Private
{
    KeyMaker keyMaker;
    Cipher::Algorithm algorithm;
    Cipher::Operation operation;
    uint keyLength;
    QByteArray initVector;

    Private(Cipher::Algorithm algorithm, Cipher::Operation operation, uint keyLength) :
        algorithm(algorithm),
        operation(operation),
        keyLength(keyLength)
    { }

    template <class Alg>
    bool decrypt(QByteArray &dst, const QByteArray &src, const QByteArray &pwd)
    {
        using namespace CryptoPP;
        SecByteBlock key(Alg::StaticGetValidKeyLength(keyLength));
        QScopedPointer<StreamTransformation> cipher;

        if (keyMaker.deriveKey(key.data(), key.size(), pwd) && !initVector.isNull()) {
            const byte *IVData = reinterpret_cast<const byte*>(initVector.constData());
            switch (operation) {
            case Cipher::CipherBlockChaining:
                cipher.reset(new typename CBC_Mode<Alg>::Decryption(key.data(), key.size(), IVData));
                break;
            case Cipher::CipherFeedback:
                cipher.reset(new typename CFB_Mode<Alg>::Decryption(key.data(), key.size(), IVData));
                break;
            case Cipher::Counter:
                cipher.reset(new typename CTR_Mode<Alg>::Decryption(key.data(), key.size(), IVData));
                break;
            case Cipher::ElectronicCodebook:
                cipher.reset(new typename ECB_Mode<Alg>::Decryption(key.data(), key.size(), IVData));
                break;
            case Cipher::OutputFeedback:
                cipher.reset(new typename OFB_Mode<Alg>::Decryption(key.data(), key.size(), IVData));
                break;
            default:
                break;
            }
        }

        if (cipher.isNull()) return false;

        try {
            std::string sink;
            StringSource(src.toStdString(), true,
                         new StreamTransformationFilter(*cipher, new StringSink(sink)));
            dst.resize(sink.size());
            std::memcpy(dst.data(), sink.data(), sink.size());
        } catch (...) {
            return false;
        }

        return true;
    }

    template <class Alg>
    bool encrypt(QByteArray &dst, const QByteArray &src, const QByteArray &pwd)
    {
        using namespace CryptoPP;
        SecByteBlock key(Alg::StaticGetValidKeyLength(16));
        QScopedPointer<StreamTransformation> cipher;
        CryptoPP::AutoSeededRandomPool prng;
        keyMaker.setSalt(QByteArray()); // will trigger KeyMaker to generate new salt
        initVector.resize(Alg::BLOCKSIZE);
        prng.GenerateBlock(reinterpret_cast<byte*>(initVector.data()), initVector.size());

        if (keyMaker.deriveKey(key.data(), key.size(), pwd) && !initVector.isNull()) {
            const byte *IVData = reinterpret_cast<const byte*>(initVector.constData());
            switch (operation) {
            case Cipher::CipherBlockChaining:
                cipher.reset(new typename CBC_Mode<Alg>::Encryption(key.data(), key.size(), IVData));
                break;
            case Cipher::CipherFeedback:
                cipher.reset(new typename CFB_Mode<Alg>::Encryption(key.data(), key.size(), IVData));
                break;
            case Cipher::Counter:
                cipher.reset(new typename CTR_Mode<Alg>::Encryption(key.data(), key.size(), IVData));
                break;
            case Cipher::ElectronicCodebook:
                cipher.reset(new typename ECB_Mode<Alg>::Encryption(key.data(), key.size(), IVData));
                break;
            case Cipher::OutputFeedback:
                cipher.reset(new typename OFB_Mode<Alg>::Encryption(key.data(), key.size(), IVData));
                break;
            default:
                break;
            }
        }

        if (cipher.isNull()) return false;

        try {
            std::string sink;
            StringSource(src.toStdString(), true,
                         new StreamTransformationFilter(*cipher, new StringSink(sink)));
            dst.resize(sink.size());
            std::memcpy(dst.data(), sink.data(), sink.size());
        } catch (...) {
            return false;
        }

        return true;
    }
};

}

using namespace QryptoPP;

const QStringList Cipher::AlgorithmNames =
        QStringList() << CryptoPP::AES::StaticAlgorithmName() <<
                         CryptoPP::Blowfish::StaticAlgorithmName() <<
                         CryptoPP::Camellia::StaticAlgorithmName() <<
                         CryptoPP::DES_EDE3::StaticAlgorithmName() <<
                         CryptoPP::IDEA::StaticAlgorithmName() <<
                         CryptoPP::SEED::StaticAlgorithmName() <<
                         CryptoPP::Serpent::StaticAlgorithmName() <<
                         CryptoPP::Twofish::StaticAlgorithmName() <<
                         QString();

const QStringList Cipher::OperationCodes =
        QStringList() << "CBC" << "CFB" << "CTR" << "ECB" << "OFB" << QString();

Cipher::Cipher(Algorithm algorithm, Operation operation, uint keyLength) :
    d(new Private(algorithm, operation, keyLength))
{ }

Cipher::Cipher(const Cipher &cipher) :
    d(new Private(*cipher.d))
{ }

Cipher::Cipher(const QString &algorithmName, const QString &operationCode, uint keyLength) :
    d(new Private(UnknownAlgorithm, UnknownOperation, keyLength))
{
    setAlgorithmName(algorithmName);
    setOperationCode(operationCode);
}

Cipher::~Cipher()
{
    delete d;
}

Cipher &Cipher::operator=(const Cipher &cipher)
{
    *d = *cipher.d;
    return *this;
}

Cipher::Algorithm Cipher::algorithm() const
{
    return d->algorithm;
}

QString Cipher::algorithmName() const
{
    return AlgorithmNames.at(d->algorithm);
}

bool Cipher::decrypt(QByteArray &plain, const QByteArray &crypt, const QByteArray &password)
{
    switch (d->algorithm) {
    case AES:
        return d->decrypt<CryptoPP::AES>(plain, crypt, password);
    case Blowfish:
        return d->decrypt<CryptoPP::Blowfish>(plain, crypt, password);
    case Camellia:
        return d->decrypt<CryptoPP::Camellia>(plain, crypt, password);
    case DES_EDE3:
        return d->decrypt<CryptoPP::DES_EDE3>(plain, crypt, password);
    case IDEA:
        return d->decrypt<CryptoPP::IDEA>(plain, crypt, password);
    case SEED:
        return d->decrypt<CryptoPP::SEED>(plain, crypt, password);
    case Serpent:
        return d->decrypt<CryptoPP::Serpent>(plain, crypt, password);
    case Twofish:
        return d->decrypt<CryptoPP::Twofish>(plain, crypt, password);
    default:
        break;
    }

    return false;
}

bool Cipher::encrypt(QByteArray &crypt, const QByteArray &plain, const QByteArray &password)
{
    switch (d->algorithm) {
    case AES:
        return d->encrypt<CryptoPP::AES>(crypt, plain, password);
    case Blowfish:
        return d->encrypt<CryptoPP::Blowfish>(crypt, plain, password);
    case Camellia:
        return d->encrypt<CryptoPP::Camellia>(crypt, plain, password);
    case DES_EDE3:
        return d->encrypt<CryptoPP::DES_EDE3>(crypt, plain, password);
    case IDEA:
        return d->encrypt<CryptoPP::IDEA>(crypt, plain, password);
    case SEED:
        return d->encrypt<CryptoPP::SEED>(crypt, plain, password);
    case Serpent:
        return d->encrypt<CryptoPP::Serpent>(crypt, plain, password);
    case Twofish:
        return d->encrypt<CryptoPP::Twofish>(crypt, plain, password);
    default:
        break;
    }

    return false;
}

QByteArray Cipher::initVector() const
{
    return d->initVector;
}

uint Cipher::keyLength() const
{
    return d->keyLength;
}

void Cipher::setKeyLength(uint keyLength)
{
    d->keyLength = keyLength;
}

KeyMaker &Cipher::keyMaker()
{
    return d->keyMaker;
}

Cipher::Operation Cipher::operation() const
{
    return d->operation;
}

QString Cipher::operationCode() const
{
    return OperationCodes.at(d->operation);
}

void Cipher::setAlgorithm(Algorithm algorithm)
{
    d->algorithm = algorithm;
}

void Cipher::setAlgorithmName(const QString &algorithmName)
{
    for (int i = UnknownAlgorithm; i-- > 0; ) {
        if (AlgorithmNames.at(i).compare(algorithmName, Qt::CaseInsensitive) == 0) {
            d->algorithm = Algorithm(i);
            return;
        }
    }

    d->algorithm = UnknownAlgorithm;
}

void Cipher::setInitVector(const QByteArray &initVector)
{
    d->initVector = initVector;
}

void Cipher::setOperation(Operation operation)
{
    d->operation = operation;
}

void Cipher::setOperationCode(const QString &operationCode)
{
    for (int i = UnknownOperation; i-- > 0; ) {
        if (OperationCodes.at(i).compare(operationCode, Qt::CaseInsensitive) == 0) {
            d->operation = Operation(i);
            return;
        }
    }

    d->operation = UnknownOperation;
}
