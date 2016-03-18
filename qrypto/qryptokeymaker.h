#ifndef QRYPTOPP_KEYMAKER_H
#define QRYPTOPP_KEYMAKER_H

#include <QByteArray>

namespace QryptoPP
{

/**
 * @brief The KeyMaker class implements PKCS5_PBKDF2_HMAC using the selected Algorithm
 */
class KeyMaker
{
    struct Private;
    Private *d;

public:
    enum Algorithm {
        RipeMD_160,
        RipeMD_320,
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Whirlpool,
        UnknownAlgorithm
    };

    KeyMaker(Algorithm algorithm = Sha1, uint iterationCount = 100000);

    KeyMaker(const QString &algorithmName, uint iterationCount);

    ~KeyMaker();

    /**
     * @brief deriveKey
     * @param keyData can be either char* or uchar*
     * @param desiredKeyLength
     * @param password should not be null
     * @return derived key length
     */
    uint deriveKey(void *keyData, uint desiredKeyLength, const QByteArray &password);

    Algorithm algorithm() const;

    void setAlgorithm(Algorithm algorithm);

    QString algorithmName() const;

    uint iterationCount() const;

    void setIterationCount(uint iterationCount);

    /**
     * @brief salt is automatically generated after deriveKey if empty
     * @return
     */
    QByteArray salt() const;

    /**
     * @brief setSalt would be used for decryption
     * @param salt
     */
    void setSalt(const QByteArray &salt);

};

}

#endif // QRYPTOPP_KEYMAKER_H
