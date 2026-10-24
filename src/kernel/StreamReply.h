#ifndef _STREAMREPLY_H_
#define _STREAMREPLY_H_
#include <sys/uio.h>
class CommSession;
class Communicator;
class StreamReply
{
public:
    struct Impl;
    int write(const struct iovec *iov, int iovcnt,
              void (*callback)(void *, int), void *context);
    int finish(void (*callback)(void *, int), void *context);
    void abort();
    bool connected() const;
private:
    Impl *impl;
    explicit StreamReply(Impl *p) : impl(p) { }
    ~StreamReply() { }
    StreamReply(const StreamReply&) = delete;
    StreamReply& operator=(const StreamReply&) = delete;
    friend class CommSession;
    friend class Communicator;
};
#endif
