#include "sequre.h"

using namespace Qrypto;

template <class Cls, class Str, typename Len, typename Chr>
Cls &Sequre<Cls, Str, Len, Chr>::append(const Str &data)
{
    resize(s->size() + data.size());
    std::copy(data.begin(), data.end(), s->end() - data.size());
    return reinterpret_cast<Cls&>(*this);
}

template <class Cls, class Str, typename Len, typename Chr>
Cls &Sequre<Cls, Str, Len, Chr>::append(const Chr *first, const Chr *last)
{
    for (int size = last - first; size > 0; size = 0) {
        resize(s->size() + size);
        std::copy(first, last, s->end() - size);
    }

    return reinterpret_cast<Cls&>(*this);
}

template <class Cls, class Str, typename Len, typename Chr>
Cls &Sequre<Cls, Str, Len, Chr>::assign(const Str &data)
{
    clear();
    *s = data;
    return reinterpret_cast<Cls&>(*this);
}

template <class Cls, class Str, typename Len, typename Chr>
Chr &Sequre<Cls, Str, Len, Chr>::at(int id) const
{
    if (id < 0)
        return *(s->end() + id);
    else
        return *(s->begin() + id);
}

template <class Cls, class Str, typename Len, typename Chr>
void Sequre<Cls, Str, Len, Chr>::clear()
{
    fill(Chr(0), s->capacity());
    s->clear();
}

template <class Cls, class Str, typename Len, typename Chr>
Cls &Sequre<Cls, Str, Len, Chr>::fill(Chr ch, Len size)
{
    resize(std::max(s->size(), size));
    std::fill(s->begin(), s->end(), ch);
    return reinterpret_cast<Cls&>(*this);
}

template <class Cls, class Str, typename Len, typename Chr>
Cls &Sequre<Cls, Str, Len, Chr>::prepend(const Str &data)
{
    Str prepend;
    prepend.resize(data.size() + s->size());
    std::copy(s->begin(), s->end(), std::copy(data.begin(), data.end(), prepend.begin()));
    clear();
    s->swap(prepend);
    return reinterpret_cast<Cls&>(*this);
}

template <class Cls, class Str, typename Len, typename Chr>
void Sequre<Cls, Str, Len, Chr>::reserve(Len capacity)
{
    if (s->capacity() < capacity) {
        Str data;
        data.reserve(capacity);
        data.resize(s->size());
        std::copy(s->begin(), s->end(), data.begin());
        clear();
        s->swap(data);
    }
}

template <class Cls, class Str, typename Len, typename Chr>
void Sequre<Cls, Str, Len, Chr>::resize(Len size)
{
    if (s->capacity() < size) {
        Str data;
        data.resize(size);
        std::copy(s->begin(), s->end(), data.begin());
        clear();
        s->swap(data);
    } else {
        s->resize(size);
    }
}

SequreStr::SequreStr(std::string *data) : super(data) { }

SequreStr::SequreStr(size_t size, char ch) : super(size, ch) { }

SequreStr::SequreStr(const SequreStr &copy) : super(*copy) { }

SequreStr::SequreStr(const std::string &str) : super(str) { }

SequreStr::SequreStr(const QByteArray &str) : super()
{ str.toStdString().swap(*string()); } // std::string does hard copy, so we use swap

SequreStr::SequreStr(const QString &str) : super()
{ str.toStdString().swap(*string()); }

SequreBytes::SequreBytes(QByteArray *data) : super(data) { }

SequreBytes::SequreBytes(int size, char ch) : super(size, ch) { }

SequreBytes::SequreBytes(const SequreBytes &copy) : super(*copy) { }

SequreBytes::SequreBytes(const QByteArray &str) : super(str) { }

SequreBytes::SequreBytes(const QString &str) : super(str.toUtf8()) { }

SequreBytes::SequreBytes(const std::string &str) : super(QByteArray::fromStdString(str)) { }

SequreString::SequreString(QString *data) : super(data) { }

SequreString::SequreString(int size, QChar ch) : super(size, ch) { }

SequreString::SequreString(const SequreString &copy) : super(*copy) { }

SequreString::SequreString(const QString &str) : super(str) { }

SequreString::SequreString(const QByteArray &str) : super(QString::fromUtf8(str)) { }

SequreString::SequreString(const std::string &str) : super(QString::fromStdString(str)) { }
