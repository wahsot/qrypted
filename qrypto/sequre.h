/* Qrypto 2019
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

#include <algorithm>

namespace Qrypto
{

template <class Str, typename Len = int, typename Chr = char>
/**
 * @brief The Sequre class sequrely clears memory before any deallocation
 * @param Str string class
 * @param Len size type
 * @param Chr value type
 */
class Sequre
{
    Str *s;

public:

    typedef Sequre<Str, Len, Chr> Cls;
    typedef Len  size_type;
    typedef Chr  value_type;
    typedef typename Str::iterator iterator;

    Sequre(Str *str = 0) :
        s(str ? str : new Str)
    { }

    Sequre(Len size, Chr ch) :
        s(new Str(size, ch))
    { }

    explicit Sequre(const Str &str) :
        s(new Str(str))
    { }

    Sequre(const Cls &copy) :
        s(new Str(*copy))
    { }

    ~Sequre()
    { delete clear().s; }

    Cls &operator=(const Cls &str)
    { return assign(*str); }

    Cls &operator=(const Str &str)
    { return assign(str); }

    Cls &operator+=(const Cls &str)
    { return append(*str); }

    Cls &operator+=(const Str &str)
    { return append(str); }

    Str &operator*() const
    { return *s; }

    Str *operator->() const
    { return s; }

    Chr &operator[](int id)
    { return *((id < 0 ? s->end() : s->begin()) + id); }

    Cls &append(Chr ch)
    { return append(&ch, 1); }

    Cls &append(const Str &str)
    { return append(str.data(), str.size()); }

    Cls &append(const Chr *str, Len size)
    {
        if (str && size > 0)
            std::copy(str, str + size, resize(s->size() + size)->end() - size);

        return *this;
    }

    Cls &assign(const Str &str)
    {
        std::copy(str.begin(), str.end(), resize(str.size())->begin());
        return *this;
    }

    iterator begin()
    { return s->begin(); }

    iterator end()
    { return s->end(); }

    Cls &clear()
    {
        for (Len size = fill(0, s->capacity())->size(); size && s->at(size / 2) == Chr(0); size = 0)
            s->clear(); // the code above should be complex enough to avoid optimisation

        return *this;
    }

    Cls &fill(Chr ch)
    { return fill(ch, s->size()); }

    Cls &fill(Chr ch, Len size)
    {
        std::fill_n(resize(size)->begin(), size, ch);
        return *this;
    }

    iterator insert(Len pos, Chr ch)
    { return insert(pos, &ch, 1); }

    iterator insert(Len pos, const Str &str)
    { return insert(pos, str.data(), str.size()); }

    iterator insert(Len pos, const Chr *str, Len size)
    {
        if (str && size > 0) {
            resize(s->size() + size);
            std::copy(str, str + size,
                      std::copy_backward(s->begin() + pos, s->begin() + (pos + size), s->end()));
        }

        return begin() + (pos + size);
    }

    Cls &prepend(Chr ch)
    { return prepend(&ch, 1); }

    Cls &prepend(const Str &str)
    { return prepend(str.data(), str.size()); }

    Cls &prepend(const Chr *str, Len size)
    {
        if (str && size > 0) {
            Str t;
            t.resize(s->size() + size);
            std::copy(s->begin(), s->end(), std::copy(str, str + size, t.begin()));
            clear()->swap(t);
        }

        return *this;
    }

    Cls &reserve(Len capacity)
    {
        if (capacity > s->capacity()) {
            Str t;
            t.reserve(capacity);
            t.resize(s->size());
            std::copy(s->begin(), s->end(), t.begin());
            clear()->swap(t);
        }

        return *this;
    }

    Cls &resize(Len size)
    {
        if (size > s->capacity()) {
            Str t;
            t.resize(size);
            std::copy(s->begin(), s->end(), t.begin());
            clear()->swap(t);
        } else {
            s->resize(size); // assumes no reallocation when resizing within capacity
        }

        return *this;
    }

    /* CryptoPP StringSinkTemplate compatibility */

    struct traits_type { typedef Chr char_type; };

    template <class InputIterator>
    Cls &append(InputIterator first, InputIterator last)
    {
        const int size = last - first;

        if (size > 0)
            std::copy(first, last, resize(s->size() + size)->end() - size);

        return *this;
    }

    Len capacity() const
    { return s->capacity(); }

    iterator insert(iterator it, const Chr *first, const Chr *last)
    {
        const Len pos = it - begin();

        if (size() == pos)
            return append(first, last).end();
        else
            return insert(pos, first, last - first);
    }

    Len size() const
    { return s->size(); }
};

}

#endif // QRYPTO_SEQURE_H
