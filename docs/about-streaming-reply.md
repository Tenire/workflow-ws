# Streaming replies

A server task can opt into a producer-driven reply before its normal task dispatch:

```cpp
StreamReply *stream = task->start_stream_reply(true);
struct iovec body = {(void *)"hello", 5};
stream->write(&body, 1, [](void *, int error) { /* 0 means accepted batch sent */ }, nullptr);
stream->finish([](void *, int error) { /* terminal framing sent */ }, nullptr);
```

`start_stream_reply(true)` uses chunk framing for each accepted body batch and sends a
zero-length terminal chunk from `finish`. Header framing remains the protocol's
responsibility: for HTTP, set `Transfer-Encoding: chunked` before starting a chunked
stream. A non-chunked stream sends borrowed body bytes as-is and requires the response
protocol to provide its own content length or close-delimited framing.

`write` accepts one batch while no previous batch is in flight. It returns `0` when
accepted and invokes its callback exactly once with `0` after the bytes have been
written, or with the transport error. A rejected call returns `-1` and does not invoke
the callback. Body buffers are borrowed until that callback; they must remain valid and
unchanged until then. Callbacks may run inline and may submit the next batch.

`finish` is accepted only after all body callbacks have completed. `abort` cancels the
transport and makes the handle disconnected. `connected()` becomes false on peer EOF,
service stop, cancellation, or transport failure. The handle is owned by the producer
and remains valid until the producer has released it and the normal server task
completion has run. The original task is not terminally handled by a stream callback;
normal workflow dispatch still completes it once the producer is done.
