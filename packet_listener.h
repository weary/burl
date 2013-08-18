#ifndef __BURL_PACKET_LISTENER_H__
#define __BURL_PACKET_LISTENER_H__

#include <boost/noncopyable.hpp>
#include "reass/packet_listener.h"
#include "request_response.h"

struct burl_settings_t;
struct http_parser_settings;

// base for something that gets requests and responses
struct page_container_t
{
	virtual void add_request(const request_ptr &req) = 0;
	virtual void add_response(const response_ptr &res) = 0;
};


class burl_packet_listener_t :
	public packet_listener_t,
	public boost::noncopyable
{
public:
	burl_packet_listener_t(burl_settings_t *settings, page_container_t *out);
	~burl_packet_listener_t();

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream);
	void accept_error(packet_t *packet, const char *error);

protected:
	burl_settings_t *d_burlsettings;
	http_parser_settings *d_httpsettings;
	page_container_t *d_container; // storage for the requests/responses
	uint64_t d_packetloss;
};

#endif // __BURL_PACKET_LISTENER_H__
