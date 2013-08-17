#include "shared/misc.h"
#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include "http-parser/http_parser.h"
#include <string>
#include <string.h>
#include <iostream>
#include <boost/scope_exit.hpp>

class packet_listener_t;

typedef std::pair<std::string, std::string> headerpair_t;
struct request_or_response_t
{
	std::vector<headerpair_t> headers;
};

struct request_t : public request_or_response_t
{
	char method; 
	std::string url;
};
typedef std::shared_ptr<request_t> request_ptr;

struct response_t : public request_or_response_t
{
	response_t() : status(0) {}

	int status;
	std::string body;
};
typedef std::shared_ptr<response_t> response_ptr;

struct page_t
{
	page_t(const request_ptr &req, const response_ptr &res) :
		d_req(req), d_res(res) {}
	~page_t() { dump(); }

	void dump();

	request_ptr d_req;
	response_ptr d_res;
};
typedef std::shared_ptr<page_t> page_ptr;

void page_t::dump()
{
	printf("%s %s\n",
			http_method_str((http_method)d_req->method),
			d_req->url.c_str());
	printf("status code %d\n", d_res->status);
	for (const auto &row: d_req->headers)
		printf("req '%s' = '%s'\n", row.first.c_str(), row.second.c_str());
	for (const auto &row: d_res->headers)
		printf("res '%s' = '%s'\n", row.first.c_str(), row.second.c_str());
	printf("%ld bytes body\n", (long)d_res->body.size());
}


struct stream_t
{
	stream_t(tcp_stream_t *stream, http_parser_settings *parsersettings) :
		d_settings(parsersettings),
		d_broken(false)
	{
		printf("new stream_t\n");
		http_parser_init(&d_parser, HTTP_BOTH);
		d_parser.data = this;
	}

	~stream_t() {}

	void accept_tcp(packet_t *packet, int packetloss, bool initiatorside)
	{
		if (d_broken)
			return;

		d_current_direction = (initiatorside ? request : response);
		BOOST_SCOPE_EXIT(&d_current_direction) {
			d_current_direction = no_direction;
    } BOOST_SCOPE_EXIT_END


		auto_release_t<packet_t> releaser(packet);
		if (packet)
		{
			layer_t *toplayer = packet->layer(-1);
			if (!toplayer || toplayer->type() != layer_data)
				return;

			size_t nparsed = http_parser_execute (
					&d_parser,
					d_settings,
					(const char *)toplayer->begin(),
					toplayer->size());

			if (d_parser.upgrade)
				d_broken = true;
			else if (nparsed != toplayer->size())
			{
				printf("nparsed = %d, expected %d\n",
						(int)nparsed, (int)toplayer->size());
				d_broken = true;
			}
		}
		else
		{
			size_t nparsed = http_parser_execute(
					&d_parser, d_settings, nullptr, 0);
			if (nparsed != 0)
				printf("nparsed = %d, expected zero\n",
						(int)nparsed);
		}
	}

	int on_url(const char *at, size_t length)
	{
		req()->method = d_parser.method;
		req()->url = std::string(at, length).c_str();
		return 0;
	}

	int on_header_field(const char *at, size_t length)
	{
		d_field.assign(at, length);
		return 0;
	}

	int on_header_value(const char *at, size_t length)
	{
		cur()->headers.push_back(headerpair_t(d_field, std::string(at, length)));
		//if (d_field == "Host")
		////	printf("%s: host = '%s'\n", cd(), std::string(at, length).c_str());
		//printf("value '%s'\n", std::string(at, length).c_str());
		return 0;
	}

	int on_body(const char *at, size_t length)
	{
		res()->body.append(at, length);
		return 0;
	}

	int on_headers_complete()
	{
		return 0;
	}

	int on_status_complete()
	{
		res()->status = d_parser.status_code;
		return 0;
	}

	int on_message_begin()
	{
		printf("%s: message begin\n", cd());
		return 0;
	}

	int on_message_complete()
	{
		if (d_current_direction == request)
		{
			printf("request completed\n");
			d_requestlist.push_back(d_current_request);
			d_current_request.reset();
		}
		else
		{
			printf("response completed\n");
			if (d_requestlist.empty())
				throw std::runtime_error("response without request");
			else
			{
				request_ptr req = d_requestlist.front();
				d_requestlist.pop_front();

				d_pagelist.push_back(page_ptr(new page_t(req, d_current_response)));
				d_pagelist.back()->dump();
				d_current_response.reset();
			}
		}
		return 0;
	}
protected:
	http_parser_settings *d_settings;
	http_parser d_parser;

	bool d_broken;
	std::string d_field;

	enum direction_t { request, response, no_direction };
	direction_t d_current_direction;

	request_ptr d_current_request;
	response_ptr d_current_response;

	// waiting for a response
	std::list<request_ptr> d_requestlist;

	// fully received request's+response's
	std::list<page_ptr> d_pagelist;

	const char *cd()
	{
		return d_current_direction == request ? "request" :
			d_current_direction == response ? "response" : "unknown";
	}

	request_or_response_t *cur()
	{
		if (d_current_direction == request) return req();
		else if (d_current_direction == response) return res();
	 	return nullptr;
	}

	request_t *req()
	{
		if (!d_current_request)
			d_current_request.reset(new request_t);
		return d_current_request.get();
	}

	response_t *res()
	{
		if (!d_current_response)
			d_current_response.reset(new response_t);
		return d_current_response.get();
	}
};

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
FORWARD_NOTIFICATION(on_headers_complete)
FORWARD_NOTIFICATION(on_message_begin)
FORWARD_NOTIFICATION(on_status_complete)
FORWARD_NOTIFICATION(on_message_complete)



class my_packet_listener_t : public packet_listener_t
{
public:
	my_packet_listener_t()
	{
		::memset(&d_settings, 0, sizeof(d_settings));
    d_settings.on_url = ::on_url;
		d_settings.on_url = ::on_url;
		d_settings.on_header_field = ::on_header_field;
		d_settings.on_header_value = ::on_header_value;
		d_settings.on_body = ::on_body;
		d_settings.on_headers_complete = ::on_headers_complete;
		d_settings.on_message_begin = ::on_message_begin;
		d_settings.on_message_complete = ::on_message_complete;
		d_settings.on_status_complete = ::on_status_complete;
	}
	~my_packet_listener_t() {}

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		stream_t *user = reinterpret_cast<stream_t *>(stream->userdata());
		stream_t *partneruser = reinterpret_cast<stream_t *>(stream->partner()->userdata());
		if (!user && !partneruser)
		{
			printf("new tcp stream, initiator = %d\n", stream->initiator());
			user = new stream_t(stream, &d_settings);
			stream->set_userdata(user);
			if (stream->have_partner())
				stream->partner()->set_userdata(user);
		}
		if (user)
			user->accept_tcp(packet, packetloss, stream->initiator());

		if (!packet)
		{
			if (!partneruser)
				delete user;
			printf("one-side shutdown\n");
			stream->set_userdata(nullptr);
		}
	}

	void accept_error(packet_t *packet, const char *error)
	{
		throw format_exception("error parsing packet '%s': %s", to_str(*packet).c_str(), error);
	}

protected:
	http_parser_settings d_settings;
};

void printhelp(const char *argv0)
{
	printf("\nprint all data in captured streams to stdout\n\n");
	printf("%s [--live <device>] [--bpf <bpf>] [pcaps]\n", basename(argv0));
}

int main(int argc, char *argv[])
	try
{
	std::vector<std::string> positional;
	bool live = false;
	std::string filter;
	for (int n=1; n<argc; ++n)
	{
		std::string arg = argv[n];
		bool havenext = n+1 < argc;
		if (havenext && (arg == "--bpf" || arg == "--filter"))
		{ filter = argv[n+1]; ++n; }
		else if (arg == "--live")
			live = true;
		else if (arg == "-h" or arg == "--help")
		{
			printhelp(argv[0]);
			return -1;
		}
		else positional.push_back(arg);
	}
	if (live && positional.size()>1)
		throw format_exception("can only do live capture on one device (use 'any' for all)");
	if (!live && positional.empty())
		throw format_exception("need at least one pcap file");

	my_packet_listener_t listener;
	pcap_reader_t reader(&listener);
	if (!live)
		for(const std::string &file: positional)
			reader.read_file(file, filter);
	else
	{
		std::string device = "any";
		if (!positional.empty())
			device = positional[0];
		reader.open_live_capture(device, true, filter);
		while (1)
			reader.read_packets();
	}
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

