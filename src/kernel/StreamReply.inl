/* Included by Communicator.cc: entry and target are deliberately private to
 * the transport implementation. All transitions use target->mutex. */
void Communicator::stream_release(StreamReply::Impl *impl)
{
    if (__sync_sub_and_fetch(&impl->references, 1) != 0)
        return;
    CommConnEntry *entry = impl->entry;
    CommServiceTarget *target = (CommServiceTarget *)entry->target;
    delete impl->handle;
    delete impl;
    if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
    {
        __release_conn(entry);
        target->decref();
    }
}

/* A batch has one absolute send deadline. Partial progress must not replace
 * a short session send_timeout with the peer response timeout. */
static int __stream_partial_written(size_t, void *) { return 0; }

int Communicator::stream_arm(StreamReply::Impl *impl, const struct iovec *iov,
                            int count, bool replace)
{
    CommConnEntry *entry = impl->entry;
    struct iovec *copy = (struct iovec *)malloc(count * sizeof *copy);
    if (!copy)
        return -1;
    memcpy(copy, iov, count * sizeof *copy);
    struct poller_data data = {};
    data.operation = PD_OP_WRITE;
    data.fd = entry->sockfd;
    data.ssl = entry->ssl;
    data.context = entry;
    data.partial_written = __stream_partial_written;
    data.write_iov = copy;
    data.iovcnt = count;
    int timeout = impl->session->send_timeout();
    int ret = replace ? mpoller_mod(&data, timeout, entry->mpoller) :
                        mpoller_add(&data, timeout, entry->mpoller);
    if (ret < 0)
    {
        free(copy);
        return -1;
    }
    entry->write_iov = copy;
    impl->node_active = true;
    return 0;
}

int Communicator::stream_watch(StreamReply::Impl *impl)
{
    struct poller_data data = {};
    data.operation = PD_OP_READ;
    data.fd = impl->entry->sockfd;
    data.ssl = impl->entry->ssl;
    data.context = impl->entry;
    data.create_message = Communicator::create_request;
    if (mpoller_add(&data, -1, impl->entry->mpoller) < 0)
        return -1;
    impl->node_active = true;
    return 0;
}

void Communicator::stream_fail(StreamReply::Impl *impl, int error)
{
    CommConnEntry *entry = impl->entry;
    if (!impl->error)
        impl->error = error;
    pthread_mutex_lock(&entry->service->mutex);
    if (entry->state == CONN_STATE_STREAMING)
        list_del(&entry->list);
    entry->state = CONN_STATE_CLOSING;
    pthread_mutex_unlock(&entry->service->mutex);
    ::shutdown(entry->sockfd, SHUT_RDWR);
}

StreamReply *Communicator::start_stream_reply(CommSession *session, bool chunked)
{
    if (!session->passive || !session->in || session->out)
    {
        errno = EINVAL;
        return NULL;
    }
    CommConnEntry *entry = session->in->entry;
    CommServiceTarget *target = (CommServiceTarget *)session->target;
    pthread_mutex_lock(&target->mutex);
    if (!entry->service->reliable || entry->is_channel ||
        entry->state != CONN_STATE_IDLE || list_empty(&target->idle_list))
    {
        pthread_mutex_unlock(&target->mutex);
        errno = ENOTCONN;
        return NULL;
    }
    StreamReply::Impl *impl = new StreamReply::Impl();
    StreamReply *handle = new StreamReply(impl);
    impl->comm = entry->communicator;
    impl->session = session;
    impl->entry = entry;
    impl->handle = handle;
    impl->chunked = chunked;
    impl->headers_pending = true;
    impl->references = 2; /* session and transferred poller-node chain */
    session->out = session->message_out();
    struct iovec vectors[ENCODE_IOV_MAX];
    int count = session->out ? session->out->encode(vectors, ENCODE_IOV_MAX) : -1;
    if (count <= 0 || count > ENCODE_IOV_MAX || stream_arm(impl, vectors, count, true) < 0)
    {
        int error = errno ? errno : EINVAL;
        session->out = NULL; /* message is embedded in the task, never delete */
        delete handle;
        delete impl;
        pthread_mutex_unlock(&target->mutex);
        errno = error;
        return NULL;
    }
    list_del(&entry->list);
    entry->stream_reply = handle;
    __sync_add_and_fetch(&entry->ref, 1); /* handle pins entry past peer EOF */
    impl->next = target->streams;
    target->streams = impl;
    pthread_mutex_lock(&entry->service->mutex);
    entry->state = CONN_STATE_STREAMING;
    list_add(&entry->list, &entry->service->keep_alive_list);
    if (entry->service->listen_fd < 0)
    {
        list_del(&entry->list);
        entry->state = CONN_STATE_CLOSING;
        impl->error = ECANCELED;
        mpoller_del(entry->sockfd, entry->mpoller);
    }
    pthread_mutex_unlock(&entry->service->mutex);
    pthread_mutex_unlock(&target->mutex);
    return handle;
}

StreamReply *CommSession::start_stream_reply(bool chunked)
{
    return Communicator::start_stream_reply(this, chunked);
}

int Communicator::stream_submit(StreamReply *stream, const struct iovec *iov,
                               int count, bool finish,
                               void (*callback)(void *, int), void *context)
{
    if (!callback || (!finish && (!iov || count <= 0 || count > ENCODE_IOV_MAX)))
    {
        errno = EINVAL;
        return -1;
    }
    StreamReply::Impl *impl = stream->impl;
    CommTarget *target = impl->entry->target;
    pthread_mutex_lock(&target->mutex);
    if (impl->error || impl->finished || impl->operation_pending || impl->detached)
    {
        int error = impl->operation_pending ? EBUSY : (impl->error ? impl->error : EPIPE);
        pthread_mutex_unlock(&target->mutex);
        errno = error;
        return -1;
    }
    size_t length = 0;
    for (int i = 0; i < count; i++)
    {
        if (iov[i].iov_len > (size_t)-1 - length || (!iov[i].iov_base && iov[i].iov_len))
        {
            pthread_mutex_unlock(&target->mutex);
            errno = EINVAL;
            return -1;
        }
        length += iov[i].iov_len;
    }
    impl->count = 0;
    if (finish && impl->chunked)
        impl->vectors[impl->count++] = {(void *)"0\r\n\r\n", 5};
    else if (!finish && length)
    {
        if (impl->chunked)
        {
            int bytes = snprintf(impl->prefix, sizeof impl->prefix, "%zx\r\n", length);
            impl->vectors[impl->count++] = {impl->prefix, (size_t)bytes};
        }
        for (int i = 0; i < count; i++)
            impl->vectors[impl->count++] = iov[i];
        if (impl->chunked)
            impl->vectors[impl->count++] = {(void *)"\r\n", 2};
    }
    impl->finishing = finish;
    impl->operation_pending = true;
    impl->callback = callback;
    impl->context = context;
    bool immediate = !impl->headers_pending && impl->count == 0;
    if (!impl->headers_pending && !immediate && stream_arm(impl, impl->vectors, impl->count, true) < 0)
    {
        int error = errno;
        impl->callback = NULL;
        impl->operation_pending = false;
        pthread_mutex_unlock(&target->mutex);
        errno = error;
        return -1;
    }
    if (immediate)
    {
        impl->callback = NULL;
        impl->operation_pending = false;
        impl->finished = finish;
    }
    pthread_mutex_unlock(&target->mutex);
    if (immediate)
        callback(context, 0);
    return 0;
}

int StreamReply::write(const struct iovec *iov, int count,
                       void (*callback)(void *, int), void *context)
{
    return Communicator::stream_submit(this, iov, count, false, callback, context);
}

int StreamReply::finish(void (*callback)(void *, int), void *context)
{
    return Communicator::stream_submit(this, NULL, 0, true, callback, context);
}

void Communicator::stream_abort(StreamReply *stream)
{
    StreamReply::Impl *impl = stream->impl;
    CommTarget *target = impl->entry->target;
    pthread_mutex_lock(&target->mutex);
    if (!impl->error && !impl->detached)
    {
        stream_fail(impl, ECANCELED);
        if (impl->node_active)
            mpoller_del(impl->entry->sockfd, impl->entry->mpoller);
    }
    pthread_mutex_unlock(&target->mutex);
}

void StreamReply::abort() { Communicator::stream_abort(this); }

bool StreamReply::connected() const
{
    CommTarget *target = impl->entry->target;
    pthread_mutex_lock(&target->mutex);
    bool connected = !impl->error && !impl->finished && !impl->detached;
    pthread_mutex_unlock(&target->mutex);
    return connected;
}

void Communicator::stream_result(struct poller_result *res)
{
    CommConnEntry *entry = (CommConnEntry *)res->data.context;
    CommTarget *target = entry->target;
    pthread_mutex_lock(&target->mutex);
    StreamReply::Impl *impl = entry->stream_reply->impl;
    __sync_add_and_fetch(&impl->references, 1); /* callback may destroy task */
    impl->node_active = false;
    int error = impl->error;
    pthread_mutex_lock(&entry->service->mutex);
    if (!error && entry->state == CONN_STATE_CLOSING)
        error = ECANCELED;
    pthread_mutex_unlock(&entry->service->mutex);
    if (!error && (res->data.operation != PD_OP_WRITE || res->state != PR_ST_FINISHED))
        error = res->error ? res->error :
            (res->state == PR_ST_DELETED || res->state == PR_ST_STOPPED ? ECANCELED : ECONNRESET);
    bool headers = impl->headers_pending;
    impl->headers_pending = false;
    if (!error && headers && impl->operation_pending && impl->count > 0)
    {
        if (stream_arm(impl, impl->vectors, impl->count, false) == 0)
        {
            pthread_mutex_unlock(&target->mutex);
            stream_release(impl);
            return;
        }
        error = errno;
    }
    if (!error && stream_watch(impl) < 0)
        error = errno;
    if (error)
        stream_fail(impl, error);
    void (*callback)(void *, int) = impl->callback;
    void *context = impl->context;
    impl->callback = NULL;
    impl->operation_pending = false;
    if (!error && impl->finishing)
        impl->finished = true;
    pthread_mutex_unlock(&target->mutex);
    if (callback)
        callback(context, error);
    if (error)
    {
        /* Final node owns the original transport reference; the handle's
         * separate entry reference keeps it available to its producer. */
        if (__sync_sub_and_fetch(&entry->ref, 1) == 0)
        {
            __release_conn(entry);
            ((CommServiceTarget *)target)->decref();
        }
        stream_release(impl); /* terminal poller-node chain */
    }
    stream_release(impl);
}

bool Communicator::stream_reply_done(CommSession *session)
{
    CommServiceTarget *target = (CommServiceTarget *)session->target;
    pthread_mutex_lock(&target->mutex);
    StreamReply::Impl *impl = target->streams;
    while (impl && impl->session != session)
        impl = impl->next;
    if (!impl)
    {
        pthread_mutex_unlock(&target->mutex);
        return false;
    }
    __sync_add_and_fetch(&impl->references, 1);
    if (!impl->error && (!impl->finished || impl->headers_pending || impl->operation_pending))
        stream_fail(impl, ECANCELED);
    CommConnEntry *entry = impl->entry;
    int error = impl->error;
    if (!error)
    {
        struct poller_data data = {};
        data.operation = PD_OP_READ;
        data.fd = entry->sockfd;
        data.ssl = entry->ssl;
        data.context = entry;
        data.create_message = Communicator::create_request;
        int timeout = session->keep_alive_timeout();
        pthread_mutex_lock(&entry->service->mutex);
        bool alive = timeout && entry->service->listen_fd >= 0;
        int ret = alive ? mpoller_mod(&data, timeout, entry->mpoller) :
                          mpoller_mod(&data, -1, entry->mpoller);
        if (ret == 0)
        {
            if (entry->state == CONN_STATE_STREAMING)
                list_del(&entry->list);
            if (alive)
            {
                entry->state = CONN_STATE_KEEPALIVE;
                list_add(&entry->list, &entry->service->keep_alive_list);
            }
            else
            {
                entry->state = CONN_STATE_CLOSING;
                mpoller_del(entry->sockfd, entry->mpoller);
            }
            entry->stream_reply = NULL;
            impl->detached = true;
            impl->node_active = false;
        }
        else
            error = ECONNRESET; /* pending EOF result still owns node chain */
        pthread_mutex_unlock(&entry->service->mutex);
        if (error)
            stream_fail(impl, error);
    }
    if (error && impl->node_active)
        mpoller_del(entry->sockfd, entry->mpoller);
    bool detached = impl->detached;
    pthread_mutex_unlock(&target->mutex);
    session->handle(error ? CS_STATE_ERROR : CS_STATE_SUCCESS, error);
    if (detached)
        stream_release(impl); /* poller node transferred to ordinary HTTP */
    stream_release(impl);
    return true;
}

void Communicator::stream_destroy(CommSession *session)
{
    CommServiceTarget *target = (CommServiceTarget *)session->target;
    pthread_mutex_lock(&target->mutex);
    StreamReply::Impl **link = &target->streams;
    while (*link && (*link)->session != session)
        link = &(*link)->next;
    StreamReply::Impl *impl = *link;
    if (impl)
    {
        *link = impl->next;
        if (!impl->detached && impl->node_active)
        {
            stream_fail(impl, ECANCELED);
            mpoller_del(impl->entry->sockfd, impl->entry->mpoller);
        }
    }
    pthread_mutex_unlock(&target->mutex);
    if (impl)
        stream_release(impl);
}
