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

_Superseded by the amendment "Stopping waits for a Batch already being delivered", below, except
for its paragraph on the Stopping flag._

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
`ClientStopped`. The flag is set on the strand there; ADR-0003 carries the matching amendment.

Reopening the socket was the alternative. A `transact` holds the raw socket across its send, so
the slot could only be replaced once nothing held it, and the Client would then carry on as if a
`bad_alloc` or a broken invariant had not happened. An Engine Discovery that throws still stops
nothing: it belongs to one Target, and only its waiters rethrow.

## Amendment, 2026-10-08: Stopping waits for a Batch already being delivered

This replaces the amendment "the batch guarantee is the strand's", above. Its paragraph on the
Stopping flag stands, except that the flag is no longer the only state outside the strand.

The Consequences above say a Batch handler is never called after destruction begins, and until now
that held only as the strand saw it. A Stopping on another thread could race a Batch the strand was
already delivering, and the handler could then run after `~Client` had returned, against state the
caller freed straight after it (#62). Nothing in the handler could tell; the caller was left with no
safe way to capture anything the destroying thread owned.

So `stop()` and `~Client` now wait for a Batch already being delivered on another thread, and for
nothing else. "Never waits" narrows to "never waits for anything that has not already started".
They do not wait on the thread delivering the Batch, which covers stopping from inside the handler;
for a Batch that has not started, which finds the flag set and is never delivered; or for anything
that needs the `io_context` to run, since a running handler needs nothing from it to return. A
receive loop that throws stops the Client on the strand, where no other thread can be delivering,
so it never waits. The Walk's completion handler is unchanged: it runs on the caller's executor and
may still run after `~Client`, as any Asio handler may.

The precedent is `std::stop_callback`, whose destructor blocks while its callback runs on another
thread and not when it runs on the destroying thread, and the mechanism is libstdc++'s for it: an
atomic records the id of the thread delivering a Batch, with no mutex. The strand records the id and
then reads the flag; Stopping sets the flag and then reads the id, waiting with `atomic::wait` while
it names another thread; the strand clears it and notifies once the handler returns. With both
sides sequentially consistent, at least one sees the other's write: either the strand finds the flag
set and calls no handler, or Stopping finds the delivery and waits for it.

The cost is the deadlock `std::stop_callback` documents too. A Batch handler must not block on
anything the thread stopping the Client may hold -- a mutex it destroys the Client under, say, or
the return of another Client's handler that is itself stopping this one -- or neither returns. A
cross-thread lock cycle cannot be detected cheaply, so it is documented on `BatchHandler` rather
than detected.

Leaving the window documented was the alternative, and it is what the earlier amendment did. Its
rule, not to capture state the destroying thread frees, is one a caller cannot keep without
synchronising with the strand itself, which is the wait moved into every caller. A mutex around
the handler call would also close it, but would hold a lock across the caller's code.

The id is a second atomic outside the strand, beside the flag; ADR-0003 carries the matching
amendment.

## Amendment, 2026-11-10: a `stop()` that cannot schedule its cleanup leaves the Client dead

`~Client` terminates when scheduling its cleanup throws; that is in its comment, and it stands.
An explicit `stop()` lets the same exception out to its caller instead, and until now what it
left behind was a claim made by inspection: the Stopping flag set, the sockets open. A test with an
executor that throws from `execute()` checked it (#66). The flag and the sockets are as claimed,
but the strand is gone too. Asio queues the cleanup on the strand and marks the strand busy before
it calls the executor underneath, and nothing clears the mark once that call throws. The strand
never runs another handler, so nothing the Client owns completes again: not its Outstanding
Requests, not at their deadlines, and not a request issued afterwards, which is not sent either.

So the exception from `stop()` is fatal to the Client, and that is the contract. The caller learns
of it, which is more than `~Client` could offer, and has to treat the Client as unusable. The
`io_context` keeps running everything else. The test stops it by hand; since the Client's sockets
stay open with receives pending on them, `run()` is not expected to return on its own.

Rolling the flag back stays rejected, for the reason b3eab6d gave: it races a concurrent `stop()`
or `~Client` that has already seen the flag and returned. It would not help anyway. The strand is
stuck in Asio, and nothing outside it can unstick it. Making `stop()` `noexcept`, so that it
terminates as `~Client` does, was the other option. It would trade an exception the caller can
log and act on, by tearing down the `io_context`, for the end of the process. That is the right
trade in a destructor, which cannot report anything, and not in a function that can.
