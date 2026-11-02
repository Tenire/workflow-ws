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

## Failure and cancellation notification

Idle event-driven producers that wait for external events before submitting data can register
a one-shot failure/cancellation callback to wake up and release their Series without polling
`connected()`:

```cpp
int ret = stream->set_close_callback([](void *context, int error) {
    auto *producer = static_cast<MyProducer *>(context);
    producer->wake_and_release(error);
}, my_producer);
```

### Registration and lifecycle

- `set_close_callback(callback, context)`:
  - Accepts one callback registration when no callback is currently armed, returning `0`.
  - While the callback is never invoked inline from within `set_close_callback`, if a terminal
    transport event occurs concurrently, the callback may run on a Communicator handler thread
    before `set_close_callback` returns to the caller. The caller must therefore fully prepare
    and validate `context` before calling `set_close_callback`.
  - Rejects null callback with `-1` and sets `errno = EINVAL`.
  - Rejects duplicate registration while a callback is armed with `-1` and sets `errno = EBUSY`.
  - Rejects calls on streams that are already failed, finishing, finished, or detached with `-1`
    and sets `errno` to the stored transport error (or `EPIPE`).

- Exactly-once notification:
  - The callback is claimed under transport lock and invoked at most once when a terminal error
    occurs (such as peer close/reset, cancellation/abort, or server stop).
  - The callback is never invoked if the stream completes normally without error.
  - Callback invocation occurs outside kernel locks from `stream_result` on a Communicator
    handler thread event path (no additional threads are spawned).

### Withdrawal contract and context validity

- `clear_close_callback()`:
  - Returns `true` if and only if an armed callback was successfully removed. Once `true` is
    returned, this specific close callback is guaranteed never to run, permitting the caller to
    safely dispose of or recycle `context` with respect to this registration. If `context` is
    shared with an in-flight `write` operation, the caller must ensure it remains valid until
    that write callback has also completed.
  - Returns `false` if no callback was removed (either none was registered, or the callback was
    already claimed/executed by `stream_result` on a handler thread).
  - A return value of `false` is NOT an unconditional promise of a future callback: the callback
    may have already completed or be executing concurrently.
  - The caller must ensure that `context` remains valid until either `clear_close_callback()`
    returns `true` or the close callback finishes execution.
### Potential write and close callback pair

If a `write` operation is in flight when the transport fails, both the operation callback and
the close callback will fire with the error code. The application is responsible for managing
context lifetimes and ensuring idempotent completion. In particular, the close context must
survive its notification even if the write callback initiates producer release.

### Normal finish ordering

- `finish()` rejects with `EBUSY` if a close callback is still armed.
- Normal completion must explicitly withdraw the subscription first via `clear_close_callback()`,
  then call `finish()`.
- If a terminal close races with this sequence, `finish()` will return `-1` with stored `errno`,
  and the caller is responsible for performing its own release.

### Detection limits and runtime cost

- Detection depends on kernel socket events (e.g. peer FIN/RST or communicator shutdown). It
  does not promise instantaneous detection for network blackholes where packets are silently
  dropped without TCP signalling; applications needing detection during silent link failures
  should configure TCP keepalives or timeouts.
- No new mutexes, condition variables, atomic operations, or reference counting are introduced.
  The implementation reuses the original transport `target->mutex`. Calling `set_close_callback`
  or `clear_close_callback` acquires this mutex, incurring standard uncontended mutex lock cost.
