#ifndef QRYPTO_POINTERATOR_H
#define QRYPTO_POINTERATOR_H

#include <algorithm>

namespace Qrypto
{

template <typename T, unsigned Chunk = 65536U / sizeof(T)>
/**
 * @brief The Pointerator class iterates through chunks of memory
 * @param T can be either const or non-const pointer, this class doesn't care
 * @param Chunk is 65kb by default, this is a strided value
 */
class Pointerator
{
    T *d;
    unsigned i;
    unsigned s;

public:

    /**
     * @brief Pointerator
     * @param data pointer to first element
     * @param size data element (total)
     */
    Pointerator(T *data = 0, unsigned size = 0) :
        d(data),
        i(0),
        s(size)
    { }

    /* Vector-like accessor API */

    T &at(unsigned id) const
    { return d[std::min(std::max(0U, i + id), s)]; }

    T *data() const
    { return d + i; }

    bool isEmpty() const
    { return !s; }

    bool isNull() const
    { return !d; }

    unsigned size() const
    { return s; }

    /* Iterator-like API
     * for (Pointerator<T> it(data, size), e = it.end(); it != e; ++it) {
     *   Pointerator<T, Chunk> chunk(*it);
     * }
     */

    typedef Pointerator<T, Chunk> const_iterator;

    const_iterator begin() const
    { return const_iterator(*this).seek(0); }

    const_iterator end() const
    { return const_iterator(*this).seek(s); }

    Pointerator<T, Chunk> operator*() const
    { return peek(); }

    bool operator==(const const_iterator &o)
    { return data() == o.data(); }

    bool operator!=(const const_iterator &o)
    { return data() != o.data(); }

    const_iterator operator++(int)
    { return read(); }

    const_iterator &operator++()
    {
        i = std::min(i + Chunk, s);
        return *this;
    }

    const_iterator &operator--()
    {
        i = std::max(0U, i - Chunk);
        return *this;
    }

    /* Javaiterator-like API
     * for (Pointerator<T> it(data, size); it.hasNext(); ) {
     *   Pointerator<T, Chunk> chunk(it.next());
     * }
     */

    bool hasNext() const
    { return i < s; }

    Pointerator<T, Chunk> next()
    { return read(); }

    /* QIODevice-like API
     * for (Pointerator<T> it(data, size); !it.atEnd(); ) {
     *   Pointerator<T, Chunk> chunk(it.read());
     * }
     */

    bool atEnd() const
    { return i == s; }

    unsigned bytesAvailable() const
    { return (s - i) * sizeof(T); }

    Pointerator<T, Chunk> peek(unsigned maxlength = Chunk) const
    { return Pointerator<T, Chunk>(data(), std::min(i + maxlength, s) - i); }

    unsigned pos() const
    { return i; }

    Pointerator<T, Chunk> read(unsigned maxlength = Chunk)
    {
        const Pointerator<T, Chunk> chunk(peek(maxlength));
        i += chunk.size();
        return chunk;
    }

    Pointerator<T, Chunk> &reset()
    { return seek(0); }

    Pointerator<T, Chunk> &seek(unsigned offset)
    {
        i = std::min(std::max(0U, offset), s);
        return *this;
    }
};

}

#endif // QRYPTO_POINTERATOR_H
