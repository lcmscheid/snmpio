// The networking half of the Asio shim (ADR-0002).
//
// detail/Asio.hpp deliberately pulls in only the error-code machinery, because the codec and the
// fuzzers need that and nothing else. Everything that actually touches a socket goes through the
// aliases here instead, so no public header ever names ::asio or ::boost::asio directly.
#ifndef SNMPIO_DETAIL_NET_HPP
#define SNMPIO_DETAIL_NET_HPP

#include <snmpio/detail/Asio.hpp>

#if defined(SNMPIO_USE_BOOST_ASIO)
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/associated_cancellation_slot.hpp>
#include <boost/asio/associated_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#else
#include <asio/any_io_executor.hpp>
#include <asio/associated_cancellation_slot.hpp>
#include <asio/associated_executor.hpp>
#include <asio/awaitable.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_executor.hpp>
#include <asio/buffer.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/cancellation_state.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/error.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/strand.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#endif

namespace snmpio::net {

#if defined(SNMPIO_USE_BOOST_ASIO)
namespace asio = ::boost::asio;
#else
namespace asio = ::asio;
#endif

using Executor = asio::any_io_executor;
using IoContext = asio::io_context;
using Strand = asio::strand<Executor>;
using SteadyTimer = asio::steady_timer;
using Udp = asio::ip::udp;
using UdpEndpoint = Udp::endpoint;
using UdpSocket = Udp::socket;

template <typename T>
using Awaitable = asio::awaitable<T>;

}  // namespace snmpio::net

#endif  // SNMPIO_DETAIL_NET_HPP
