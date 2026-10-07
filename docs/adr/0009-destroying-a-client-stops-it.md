# Destroying a Client stops it

Until now the Client's state lived in the Client itself, and every operation captured a raw `this`.
That made the Client's lifetime the caller's problem: `Client.hpp` asked callers to `stop()` and let
the `io_context` drain before destroying it, and `~Client` deliberately did not stop, because the
cleanup runs on the strand and would be scheduled against an object that was about to stop
existing. A forgotten `stop()` was a use-after-free.

That is not the contract Asio's own I/O objects keep. A socket can be destroyed with operations
outstanding: they complete with `operation_aborted`, and nothing touches freed memory. A Command
Generator embedded in a control system, which owns the `io_context` and fires requests from many
places, should be held to the same rule, since a caller who keeps that rule for sockets will assume
it here.

So the Client's state moves into a shared implementation that every Outstanding Request co-owns,
and `~Client` performs Stopping. The only lifetime rule left to the caller is Asio's own: the
`io_context` must outlive the work scheduled on it.

## Considered options

- **Keep the contract and catch violations** with a debug assertion in `~Client`. Cheaper, but it
  turns a memory-safety hole into a debug-build crash and leaves release builds exactly as exposed.
- **Make the Client itself shared** (`std::shared_ptr<Client>` and `enable_shared_from_this`).
  Safe, but it pushes the ownership model into every call site, and nothing Asio ships asks that.

## Consequences

Outstanding Requests of a destroyed Client complete with `Errc::ClientStopped`, the same code an
explicit `stop()` gives, and not `operation_aborted`. Destruction is an implicit stop. Cancellation
already owns `operation_aborted`, and ADR-0008's reasoning is that a code meaning two different
things is one no caller can branch on.

A streaming Walk's batch handler is never called after destruction begins, as the strand sees it:
destruction on the strand, or one that happens-before the strand reaches the batch. Destruction on
another thread can race a batch already being delivered, and closing that window would mean
`~Client` waiting for the handler -- the one thing it must never do, since it may be running on the
strand or with the `io_context` stopped. Completion handlers still run, on the caller's executor,
after the Client is gone, so they must not reach back into it.

ADR-0003 stands: one Client still owns the transport and the caches. They are now reached through
a shared implementation rather than held directly. It gains one exception to "internal state is
only ever touched on that strand": the Stopping flag, an atomic written by `stop()` and `~Client` on
the calling thread, so that Stopping takes effect before the strand gets round to the cleanup.

The Client stays non-copyable and non-movable. The shared implementation would make moving cheap,
but a moved-from state is one more state every member must handle, and it buys no safety. A caller
who needs to move one holds a `std::unique_ptr<Client>`.
