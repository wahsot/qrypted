#include "../qryptocipher.h"

#include "../qryptokeymaker.h"

#include <QScopedPointer>

#include <cryptopp/camellia.h>
#include <cryptopp/cast.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/blowfish.h>
#include <cryptopp/des.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/idea.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/secblock.h>
#include <cryptopp/seed.h>
#include <cryptopp/serpent.h>
#include <cryptopp/twofish.h>

#include <ctime>

namespace Qrypto
{

struct Cipher::Private
{
    static const Qrypto::Error ExceptionTypes[7];
    Qrypto::Error error;
    Cipher::Algorithm algorithm;
    Cipher::Operation operation;
    uint keyLength;
    KeyMaker keyMaker;
    QByteArray authentication;
    QByteArray initialVector;

    Private(Cipher::Algorithm algorithm, Cipher::Operation operation, uint keyLength) :
        error(Qrypto::NoError),
        algorithm(algorithm),
        operation(operation),
        keyLength(keyLength)
    { }

    template <class Alg>
    CryptoPP::StreamTransformation *getDecryption()
    {
        switch (operation) {
        case Cipher::CipherBlockChaining:
            return new typename CryptoPP::CBC_Mode<Alg>::Decryption;
        case Cipher::CipherFeedback:
            return new typename CryptoPP::CFB_Mode<Alg>::Decryption;
        case Cipher::Counter:
            return new typename CryptoPP::CTR_Mode<Alg>::Decryption;
        case Cipher::EncryptAuthenticateTranslate:
            return new typename CryptoPP::EAX<Alg>::Decryption;
        case Cipher::GaloisCounter:
            return new typename CryptoPP::GCM<Alg>::Decryption;
        case Cipher::OutputFeedback:
            return new typename CryptoPP::OFB_Mode<Alg>::Decryption;
        default:
            return 0;
        }
    }

    template <class Alg>
    CryptoPP::StreamTransformation *getEncryption()
    {
        initialVector.resize(Alg::BLOCKSIZE);

        switch (operation) {
        case Cipher::CipherBlockChaining:
            return new typename CryptoPP::CBC_Mode<Alg>::Encryption;
        case Cipher::CipherFeedback:
            return new typename CryptoPP::CFB_Mode<Alg>::Encryption;
        case Cipher::Counter:
            return new typename CryptoPP::CTR_Mode<Alg>::Encryption;
        case Cipher::EncryptAuthenticateTranslate:
            return new typename CryptoPP::EAX<Alg>::Encryption;
        case Cipher::GaloisCounter:
            return new typename CryptoPP::GCM<Alg>::Encryption;
        case Cipher::OutputFeedback:
            return new typename CryptoPP::OFB_Mode<Alg>::Encryption;
        default:
            return 0;
        }
    }

    bool decrypt(CryptoPP::Algorithm *cipher, QByteArray &dst, const QByteArray &src, const QByteArray &pwd)
    {
        using namespace CryptoPP;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);
        StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
        AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
        keyLength = keyMaker.deriveKey(keying->GetValidKeyLength(keyLength), pwd);

        if (keyLength && !initialVector.isNull()) {
            std::string str;
            QScopedPointer<StringSink> sink(new StringSink(str));
            const byte *IVData = reinterpret_cast<const byte*>(initialVector.constData());
            keying->SetKeyWithIV(keyMaker.keyData(), keyLength, IVData, initialVector.size());

            if (authentic) {
                StringSource(src.toStdString(), true,
                             new AuthenticatedDecryptionFilter(*authentic, sink.take()));
            } else {
                StringSource(src.toStdString(), true,
                             new StreamTransformationFilter(*stream, sink.take()));

                if (!authentication.isEmpty() && keyMaker.authenticate(str.data(), str.size()) != authentication)
                    throw HashVerificationFilter::HashVerificationFailed();
            }

            QByteArray::fromStdString(str).swap(dst);
            return true;
        }

        return false;
    }

    bool encrypt(CryptoPP::Algorithm *cipher, QByteArray &dst, const QByteArray &src, const QByteArray &pwd)
    {
        using namespace CryptoPP;
        AutoSeededRandomPool prng;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);

        for (QByteArray salt(initialVector.size(), Qt::Uninitialized); !salt.isEmpty(); salt.clear()) {
            prng.GenerateBlock(reinterpret_cast<byte*>(salt.data()), salt.size());
            keyMaker.setSalt(salt);
            keyLength = keyMaker.deriveKey(keying->GetValidKeyLength(keyLength), pwd);
        }

        while (initialVector.size() <= int(sizeof(time_t)))
            initialVector.resize(initialVector.size() * 2); // ensure IV is longer than ‘nonce’

        if (keyMaker.keyLength()) {
            std::string str;
            QScopedPointer<StringSink> sink(new StringSink(str));
            StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
            AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
            byte *IVData = reinterpret_cast<byte*>(initialVector.data());
            std::time(reinterpret_cast<time_t*>(IVData)); // begin IV with timestamp as ‘nonce’
            prng.GenerateBlock(IVData + sizeof(time_t), initialVector.size() - sizeof(time_t));
            keying->SetKeyWithIV(keyMaker.keyData(), keyLength, IVData, initialVector.size());

            if (authentic) {
                StringSource(src.toStdString(), true,
                             new AuthenticatedEncryptionFilter(*authentic, sink.take()));
                QByteArray::fromStdString(str).swap(dst);
                authentication.clear();
            } else {
                StringSource(src.toStdString(), true,
                             new StreamTransformationFilter(*stream, sink.take()));
                QByteArray::fromStdString(str).swap(dst);
                authentication = keyMaker.authenticate(src);
            }

            return true;
        }

        return false;
    }
};

}

using namespace Qrypto;

const QStringList Cipher::AlgorithmNames =
        QStringList() << CryptoPP::AES::StaticAlgorithmName() <<
                         CryptoPP::Blowfish::StaticAlgorithmName() <<
                         CryptoPP::CAST128::StaticAlgorithmName() <<
                         CryptoPP::Camellia::StaticAlgorithmName() <<
                         CryptoPP::DES_EDE3::StaticAlgorithmName() <<
                         CryptoPP::IDEA::StaticAlgorithmName() <<
                         CryptoPP::SEED::StaticAlgorithmName() <<
                         CryptoPP::Serpent::StaticAlgorithmName() <<
                         CryptoPP::Twofish::StaticAlgorithmName() <<
                         QString();

const QStringList Cipher::OperationCodes =
        QStringList() << "CBC" << "CFB" << "CTR" << "EAX" << "GCM" << "OFB" << QString();

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

QByteArray Cipher::authentication() const
{
    return d->authentication;
}

bool Cipher::decrypt(QByteArray &plain, const QByteArray &crypt, const QByteArray &password)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;
    d->error = NoError;

    switch (d->algorithm) {
    case AES:
        cipher.reset(d->getDecryption<CryptoPP::AES>());
        break;
    case Blowfish:
        cipher.reset(d->getDecryption<CryptoPP::Blowfish>());
        break;
    case CAST_128:
        cipher.reset(d->getDecryption<CryptoPP::CAST128>());
        break;
    case Camellia:
        cipher.reset(d->getDecryption<CryptoPP::Camellia>());
        break;
    case DES_EDE3:
        cipher.reset(d->getDecryption<CryptoPP::DES_EDE3>());
        break;
    case IDEA:
        cipher.reset(d->getDecryption<CryptoPP::IDEA>());
        break;
    case SEED:
        cipher.reset(d->getDecryption<CryptoPP::SEED>());
        break;
    case Serpent:
        cipher.reset(d->getDecryption<CryptoPP::Serpent>());
        break;
    case Twofish:
        cipher.reset(d->getDecryption<CryptoPP::Twofish>());
        break;
    default:
        d->error = NotImplemented;
    }

    try {
        return cipher && d->decrypt(cipher.data(), plain, crypt, password);
    } catch (const std::bad_alloc &exc) {
        d->error = OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            d->error = NotImplemented;
            break;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            d->error = InvalidArgument;
            break;
        case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED:
            d->error = IntegrityError;
            break;
        case CryptoPP::Exception::INVALID_DATA_FORMAT:
            d->error = InvalidFormat;
            break;
        default:
            qCritical(exc.what());
            d->error = UnknownError;
        }
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        d->error = UnknownError;
    }

    return false;
}

bool Cipher::encrypt(QByteArray &crypt, const QByteArray &plain, const QByteArray &password)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;
    d->error = NoError;

    switch (d->algorithm) {
    case AES:
        cipher.reset(d->getEncryption<CryptoPP::AES>());
        break;
    case Blowfish:
        cipher.reset(d->getEncryption<CryptoPP::Blowfish>());
        break;
    case CAST_128:
        cipher.reset(d->getEncryption<CryptoPP::CAST128>());
        break;
    case Camellia:
        cipher.reset(d->getEncryption<CryptoPP::Camellia>());
        break;
    case DES_EDE3:
        cipher.reset(d->getEncryption<CryptoPP::DES_EDE3>());
        break;
    case IDEA:
        cipher.reset(d->getEncryption<CryptoPP::IDEA>());
        break;
    case SEED:
        cipher.reset(d->getEncryption<CryptoPP::SEED>());
        break;
    case Serpent:
        cipher.reset(d->getEncryption<CryptoPP::Serpent>());
        break;
    case Twofish:
        cipher.reset(d->getEncryption<CryptoPP::Twofish>());
        break;
    default:
        d->error = NotImplemented;
    }

    try {
        return cipher && d->encrypt(cipher.data(), crypt, plain, password);
    } catch (const std::bad_alloc &exc) {
        d->error = OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            d->error = NotImplemented;
            break;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            d->error = InvalidArgument;
            break;
        default:
            qCritical(exc.what());
            d->error = UnknownError;
        }
    } catch (const std::exception &exc) {
        qCritical(exc.what());
        d->error = UnknownError;
    }

    return false;
}

Error Cipher::error() const
{
    return d->error;
}

QByteArray Cipher::initialVector() const
{
    return d->initialVector;
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

void Cipher::setAuthentication(const QByteArray &authentication)
{
    d->authentication = authentication;
}

void Cipher::setInitialVector(const QByteArray &initVector)
{
    d->initialVector = initVector;
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
