#ifndef __BURL_STREAM_H__
#define __BURL_STREAM_H__

#include "request_response.h"

#include <boost/noncopyable.hpp>
#include <string>

// http parser forwards
struct http_parser_settings;
struct http_parser;

// reass forwards
struct packet_t;

// burl forwards
struct burl_settings_t;
struct tcp_stream_t;
class request_listener_t;

// one side of a tcp-connection
struct stream_t :
	public boost::noncopyable
{
	stream_t(
			tcp_stream_t *stream,
			burl_settings_t *burlsettings,
			http_parser_settings *parsersettings,
			request_listener_t *container);

	~stream_t();

	void accept_packet(packet_t *packet, int packetloss);

	int on_url(const char *at, size_t length);
	int on_header_field(const char *at, size_t length);
	int on_header_value(const char *at, size_t length);
	int on_body(const char *at, size_t length);
	int on_status_complete();
	int on_message_begin();
	int on_message_complete();

protected:
	burl_settings_t *d_burlsettings;
	http_parser_settings *d_httpsettings;
	http_parser *d_parser;

	unsigned d_streamid; // counter for tcp-streams. same for initiator and responder

	request_listener_t *d_container;

	struct timeval d_now;

	bool d_broken = false;
	enum { stream_unknown, stream_partial, stream_ok } d_stream_state = stream_unknown;
	// partial means we missed packets somewhere

	std::string d_field; // for http-headers

	request_ptr d_current_request;
	response_ptr d_current_response;

	void reset_http_parser();

	bool is_request() const;
	request_or_response_t *cur();
	request_t *req();
	response_t *res();
};

#endif // __BURL_STREAM_H__
