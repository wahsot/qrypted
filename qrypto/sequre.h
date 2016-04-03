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
#ifndef QRYPTO_SEQURE_H
#define QRYPTO_SEQURE_H

#include <QString>

namespace Qrypto
{

template <class Cls, class Str, typename Len = int, typename Chr = char>
/**
 * @brief The Sequre class sequrely clears memory before any deallocation
 * @param Cls couriouslyrecursive class
 * @param Str string class
 * @param Len size type
 * @param Chr value type
 */
class Sequre
{
    Str *s;

public:

    typedef Len  size_type;
    typedef Chr  value_type;
    typedef Chr* iterator;

    Sequre(Str *str = 0) : s(str ? str : new Str) { }

    Sequre(Len size, Chr ch) : s(new Str(size, ch)) { }

    Sequre(const Cls &copy) : s(new Str(*copy)) { }

    explicit Sequre(const Str &str) : s(new Str(str)) { }

    virtual ~Sequre()
    {
        clear();
        delete s;
    }

    inline Cls &operator=(const Cls &seq)
    { return assign(*seq); }

    inline Chr &operator[](int id) const
    { return at(id); }

    /* you may access the underlying string with these functions, beware of triggering any reallocs */

    inline Str &operator*() const
    { return *s; }

    inline Str *operator->() const
    { return s; }

    inline Str *string() const
    { return s; }

    inline Cls &operator+=(const Str &data)
    { return append(data); }

    inline Cls &operator+=(const Cls &seq)
    { return append(*seq); }

    inline Cls operator+(const Str &data) const
    { return Cls(*this) += data; }

    inline Cls operator+(const Cls &seq) const
    { return Cls(*this) += seq; }

    virtual Cls &append(const Str &data);

    virtual Cls &append(const Chr *first, const Chr *last);

    virtual Cls &assign(const Str &data);

    /**
     * @brief at
     * @param id
     * @return
     */
    virtual Chr &at(int id) const;

    inline Len capacity() const
    { return s->capacity(); }

    virtual void clear();

    /**
     * @brief fill all characters to ch
     * @param ch
     * @param size to resize if non zero
     * @return
     */
    virtual Cls &fill(Chr ch, Len size = 0);

    virtual Cls &prepend(const Str &data);

    virtual void reserve(Len capacity);

    virtual void resize(Len size);

    inline Len size() const
    { return s->size(); }

};

/**
 * @brief The SequreStr class sequrely wraps std::string
 */
class SequreStr : public Sequre<SequreStr, std::string, size_t>
{
    typedef Sequre<SequreStr, std::string, size_t> super;

public:

    typedef std::string::traits_type traits_type;

    SequreStr(std::string *data = 0);

    SequreStr(size_t size, char ch);

    SequreStr(const SequreStr &copy);

    explicit SequreStr(const std::string &str);

    explicit SequreStr(const QByteArray &str);

    explicit SequreStr(const QString &str);

};

/**
 * @brief The SequreBytes class sequrely wraps QByteArray
 */
class SequreBytes : public Sequre<SequreBytes, QByteArray>
{
    typedef Sequre<SequreBytes, QByteArray> super;

public:

    typedef std::string::traits_type traits_type;

    SequreBytes(QByteArray *data = 0);

    SequreBytes(int size, char ch);

    SequreBytes(const SequreBytes &copy);

    explicit SequreBytes(const QByteArray &str);

    explicit SequreBytes(const QString &str);

    explicit SequreBytes(const std::string &str);

};

/**
 * @brief The SequreString class sequrely wraps QString
 */
class SequreString : public Sequre<SequreString, QString, int, QChar>
{
    typedef Sequre<SequreString, QString, int, QChar> super;

public:

    struct traits_type
    {
        typedef QChar char_type;
        typedef ushort int_type;
    };

    SequreString(QString *data = 0);

    SequreString(int size, QChar ch);

    SequreString(const SequreString &copy);

    explicit SequreString(const QString &str);

    explicit SequreString(const QByteArray &str);

    explicit SequreString(const std::string &str);

};

}

#endif // QRYPTO_SEQURE_H
