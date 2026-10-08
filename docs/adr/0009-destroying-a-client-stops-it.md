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

A streaming Walk's batch handler is never called after destruction begins. Completion handlers still
run, on the caller's executor, after the Client is gone, so they must not reach back into it.

The Client stays non-copyable and non-movable. The shared implementation would make moving cheap,
but a moved-from state is one more state every member must handle, and it buys no safety. A caller
who needs to move one holds a `std::unique_ptr<Client>`.

ADR-0003 is unchanged: one Client still owns the transport and the caches. They are now reached
through a shared implementation rather than held directly.

## Amendment, 2026-10-08: the batch guarantee is the strand's

The Consequences above say a batch handler is never called after destruction begins. That holds as
the strand sees it: for a destruction on the strand, or one that happens-before the strand reaches
the batch. A destruction on another thread can race a batch the strand is already delivering, and
the handler can then run after `~Client` has returned. Closing that window would mean `~Client`
waiting for the handler, which it must never do: it may be running on the strand, or with the
`io_context` stopped. Whether to wait off the strand only is #62.

The Stopping flag is also the one piece of state not confined to the strand, against ADR-0003's
"internal state is only ever touched on that strand". It is an atomic, written by `stop()` and
`~Client` on the calling thread, so that Stopping takes effect before the strand gets round to the
cleanup. ADR-0003 carries the matching amendment.

## Amendment, 2026-10-08: a receive loop that throws stops the Client too

Stopping now has a third start, besides `stop()` and `~Client`: an exception escaping a receive
loop. That loop serves every Target on its socket, so the fault belongs to the Client and not to
any one Target. Before this, the exception left `run()` (threat-model L7), but the socket stayed
open with nothing reading it, and a caller who ran the `io_context` again saw every later request
on it time out with nothing to say why (#63). The loop's completion now stops the Client before
rethrowing, on the strand, so the cleanup runs inline and the requests complete with
`ClientStopped`. The flag is set on the strand there, which keeps within ADR-0003's amendment.

Reopening the socket was the alternative. A `transact` holds the raw socket across its send, so
the slot could only be replaced once nothing held it, and the Client would then carry on as if a
`bad_alloc` or a broken invariant had not happened. An Engine Discovery that throws still stops
nothing: it belongs to one Target, and only its waiters rethrow.
