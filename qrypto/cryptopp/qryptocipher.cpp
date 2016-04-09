#include "../qryptocipher.h"

#include "../qryptokeymaker.h"
#include "../sequre.h"

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

typedef CryptoPP::StringSinkTemplate<SequreBytes> SequreSink;

struct Cipher::Private
{
    Cipher::Algorithm algorithm;
    Cipher::Operation operation;
    QByteArray authentication;
    QByteArray initialVector;

    Private(Cipher::Algorithm algorithm, Cipher::Operation operation) :
        algorithm(algorithm),
        operation(operation)
    { }

    template <class Alg>
    CryptoPP::StreamTransformation *getDecryption()
    {
        switch (operation) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Decryption;
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Decryption;
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Decryption;
        case Cipher::EAX:
            return new typename CryptoPP::EAX<Alg>::Decryption;
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Decryption;
        case Cipher::GCM:
            return new typename CryptoPP::GCM<Alg>::Decryption;
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Decryption;
        default:
            return 0;
        }
    }

    template <class Alg>
    CryptoPP::StreamTransformation *getEncryption()
    {
        switch (operation) {
        case Cipher::CBC:
            return new typename CryptoPP::CBC_Mode<Alg>::Encryption;
        case Cipher::CFB:
            return new typename CryptoPP::CFB_Mode<Alg>::Encryption;
        case Cipher::CTR:
            return new typename CryptoPP::CTR_Mode<Alg>::Encryption;
        case Cipher::EAX:
            return new typename CryptoPP::EAX<Alg>::Encryption;
        case Cipher::ECB:
            return new typename CryptoPP::ECB_Mode<Alg>::Encryption;
        case Cipher::GCM:
            return new typename CryptoPP::GCM<Alg>::Encryption;
        case Cipher::OFB:
            return new typename CryptoPP::OFB_Mode<Alg>::Encryption;
        default:
            return 0;
        }
    }

    Qrypto::Error decrypt(CryptoPP::Algorithm *cipher, SequreBytes &dst, const QByteArray &src, const KeyMaker &keyMaker)
    {
        using namespace CryptoPP;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);

        if (keying->IsValidKeyLength(keyMaker.keyLength())) {
            QScopedPointer<SequreSink> sink(new SequreSink(dst));
            StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
            AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
            dst.reserve(src.size());

            if (keying->IVSize()) {
                keying->SetKeyWithIV(keyMaker.keyData(), keyMaker.keyLength(),
                                     reinterpret_cast<const byte*>(initialVector.constData()),
                                     initialVector.size());
            } else {
                keying->SetKey(keyMaker.keyData(), keyMaker.keyLength());
            }

            if (authentic) {
                StringSource(src.toStdString(), true,
                             new AuthenticatedDecryptionFilter(*authentic, sink.take()));
            } else {
                StringSource(src.toStdString(), true,
                             new StreamTransformationFilter(*stream, sink.take()));

                if (!authentication.isEmpty() && keyMaker.authenticate(*dst) != authentication)
                    throw HashVerificationFilter::HashVerificationFailed();
            }

            return NoError;
        } else {
            throw InvalidKeyLength(cipher->AlgorithmName(), keyMaker.keyLength());
        }
    }

    Qrypto::Error encrypt(CryptoPP::Algorithm *cipher, QByteArray &dst, const SequreBytes &src, const KeyMaker &keyMaker)
    {
        using namespace CryptoPP;
        SimpleKeyingInterface *keying = dynamic_cast<SimpleKeyingInterface*>(cipher);

        if (keying->IsValidKeyLength(keyMaker.keyLength())) {
            const SequreStr plain(*src);
            std::string str;
            QScopedPointer<StringSink> sink(new StringSink(str));
            StreamTransformation *stream = dynamic_cast<StreamTransformation*>(cipher);
            AuthenticatedSymmetricCipher *authentic = dynamic_cast<AuthenticatedSymmetricCipher*>(stream);
            str.reserve(src.size());
            initialVector.resize(keying->IVSize());

            if (keying->IVSize()) {
                AutoSeededRandomPool prng;
                keying->GetNextIV(prng, reinterpret_cast<byte*>(initialVector.data()));
                keying->SetKeyWithIV(keyMaker.keyData(), keyMaker.keyLength(),
                                     reinterpret_cast<byte*>(initialVector.data()));
            } else {
                keying->SetKey(keyMaker.keyData(), keyMaker.keyLength());
            }

            if (authentic) {
                StringSource(*plain, true,
                             new AuthenticatedEncryptionFilter(*authentic, sink.take()));
                authentication.clear();
            } else {
                StringSource(*plain, true,
                             new StreamTransformationFilter(*stream, sink.take()));
                authentication = keyMaker.authenticate(*src);
            }

            QByteArray::fromStdString(str).swap(dst);
            return NoError;
        } else {
            throw InvalidKeyLength(cipher->AlgorithmName(), keyMaker.keyLength());
        }
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
        QStringList() << "CBC" << "CFB" << "CTR" << "ECB" << "EAX" << "GCM" << "OFB" << QString();

Cipher::Cipher(Algorithm algorithm, Operation operation) :
    d(new Private(algorithm, operation))
{ }

Cipher::Cipher(const Cipher &cipher) :
    d(new Private(*cipher.d))
{ }

Cipher::Cipher(const QString &algorithmName, const QString &operationCode) :
    d(new Private(UnknownAlgorithm, UnknownOperation))
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

Error Cipher::decrypt(SequreBytes &plain, const QByteArray &crypt, const KeyMaker &keyMaker)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;

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
        return NotImplemented;
    }

    try {
        return d->decrypt(cipher.data(), plain, crypt, keyMaker);
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        qCritical(exc.what());

        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            return NotImplemented;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            return InvalidArgument;
        case CryptoPP::Exception::DATA_INTEGRITY_CHECK_FAILED:
            return IntegrityError;
        case CryptoPP::Exception::INVALID_DATA_FORMAT:
            return InvalidFormat;
        default:
            return UnknownError;
        }
    }
}

Error Cipher::encrypt(QByteArray &crypt, const SequreBytes &plain, const KeyMaker &keyMaker)
{
    QScopedPointer<CryptoPP::Algorithm> cipher;

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
        break;
    }

    if (cipher.isNull())
        return NotImplemented;

    try {
        return d->encrypt(cipher.data(), crypt, plain, keyMaker);
    } catch (const std::bad_alloc &exc) {
        return OutOfMemory;
    } catch (const CryptoPP::Exception &exc) {
        qCritical(exc.what());

        switch (exc.GetErrorType()) {
        case CryptoPP::Exception::NOT_IMPLEMENTED:
            return NotImplemented;
        case CryptoPP::Exception::INVALID_ARGUMENT:
            return InvalidArgument;
        default:
            return UnknownError;
        }
    }
}

QByteArray Cipher::initialVector() const
{
    return d->initialVector;
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

uint Cipher::validateKeyLength(uint keyLength)
{
    switch (d->algorithm) {
    case AES:
        return CryptoPP::Rijndael_Info::StaticGetValidKeyLength(keyLength);
    case Blowfish:
        return CryptoPP::Blowfish_Info::StaticGetValidKeyLength(keyLength);
    case CAST_128:
        return CryptoPP::CAST128_Info::StaticGetValidKeyLength(keyLength);
    case Camellia:
        return CryptoPP::Camellia_Info::StaticGetValidKeyLength(keyLength);
    case DES_EDE3:
        return CryptoPP::DES_EDE3_Info::StaticGetValidKeyLength(keyLength);
    case IDEA:
        return CryptoPP::IDEA_Info::StaticGetValidKeyLength(keyLength);
    case SEED:
        return CryptoPP::SEED_Info::StaticGetValidKeyLength(keyLength);
    case Serpent:
        return CryptoPP::Serpent_Info::StaticGetValidKeyLength(keyLength);
    case Twofish:
        return CryptoPP::Twofish_Info::StaticGetValidKeyLength(keyLength);
    default:
        return 0;
    }
}
