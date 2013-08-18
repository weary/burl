#include "packet_listener.h"
#include "stream.h"
#include "http-parser/http_parser.h"
#include "reass/tcp_reassembler.h"

#define FORWARD_DATA(FUNC) \
static int FUNC(http_parser *parser, const char *at, size_t length) \
{ return reinterpret_cast<stream_t *>(parser->data)->FUNC(at, length); }
#define FORWARD_NOTIFICATION(FUNC) \
static int FUNC(http_parser *parser) \
{ return reinterpret_cast<stream_t *>(parser->data)->FUNC(); }

FORWARD_DATA(on_url)
FORWARD_DATA(on_header_field)
FORWARD_DATA(on_header_value)
FORWARD_DATA(on_body)
//FORWARD_NOTIFICATION(on_headers_complete)
FORWARD_NOTIFICATION(on_message_begin)
FORWARD_NOTIFICATION(on_status_complete)
FORWARD_NOTIFICATION(on_message_complete)

burl_packet_listener_t::burl_packet_listener_t(
		burl_settings_t *burlsettings,
		page_container_t *out) :
	d_burlsettings(burlsettings),
	d_container(out), d_packetloss(0)
{
	d_httpsettings = new http_parser_settings;
	::memset(d_httpsettings, 0, sizeof(d_httpsettings));
	d_httpsettings->on_url = ::on_url;
	d_httpsettings->on_url = ::on_url;
	d_httpsettings->on_header_field = ::on_header_field;
	d_httpsettings->on_header_value = ::on_header_value;
	d_httpsettings->on_body = ::on_body;
	//d_httpsettings->on_headers_complete = ::on_headers_complete;
	d_httpsettings->on_message_begin = ::on_message_begin;
	d_httpsettings->on_message_complete = ::on_message_complete;
	d_httpsettings->on_status_complete = ::on_status_complete;
}

burl_packet_listener_t::~burl_packet_listener_t()
{
	delete d_httpsettings;
	d_httpsettings = nullptr;
}

void burl_packet_listener_t::accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
{
	auto_release_t<packet_t> releaser(packet);

	// new side of a connection. we deal with both sides completely independant

	d_packetloss += packetloss;

	stream_t *user = reinterpret_cast<stream_t *>(stream->userdata());
	if (!user)
	{
		user = new stream_t(
				stream,
				d_burlsettings,
				d_httpsettings,
				d_container);
		stream->set_userdata(user);
	}
	if (user)
		user->accept_packet(packet, packetloss);

	if (!packet)
	{
		delete user;
		stream->set_userdata(nullptr);
	}
}

void burl_packet_listener_t::accept_error(packet_t *packet, const char *error)
{
	throw format_exception("error parsing packet '%s': %s", to_str(*packet).c_str(), error);
}
