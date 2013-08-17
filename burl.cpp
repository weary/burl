#include "shared/misc.h"
#include "reass/packet.h"
#include "reass/packet_listener.h"
#include "reass/pcap_reader.h"
#include "reass/pcap_writer.h"
#include "reass/tcp_reassembler.h"
#include "http-parser/http_parser.h"
#include <unordered_map>
#include <string>
#include <string.h>
#include <iostream>

class packet_listener_t;

bool g_capture_postdata = true;
bool g_capture_responsedata = true;
bool g_must_be_http = false; // if we are sure it is http restart after parse-error (otherwise we probably got a non-http stream)

typedef std::pair<std::string, std::string> headerpair_t;
struct request_or_response_t
{
	request_or_response_t() : bodysize(0), complete(false) {}

	std::string header_first(const std::string &key, const std::string default_=std::string());

	std::vector<headerpair_t> headers;
	std::string body;
	uint64_t bodysize; // if we don't capture the body, at least store the size
	unsigned tcp_streamid;
	bool complete;
};

struct request_t : public request_or_response_t
{
	const char *method_str() const { return ::http_method_str(method); }

	http_method method;
	std::string url;
};
typedef std::shared_ptr<request_t> request_ptr;

struct response_t : public request_or_response_t
{
	response_t() : status(0) {}

	int status;
};
typedef std::shared_ptr<response_t> response_ptr;

struct page_container_t
{
	virtual void add_request(const request_ptr &req) = 0;
	virtual void add_response(const response_ptr &res) = 0;
};


std::string request_or_response_t::header_first(const std::string &key, const std::string default_)
{
	for(const headerpair_t &pair: headers)
		if (pair.first == key)
			return pair.second;
	return default_;
}


// one side of a tcp-connection
struct stream_t
{
	stream_t(
			tcp_stream_t *stream,
			http_parser_settings *parsersettings,
			page_container_t *container) :
		d_settings(parsersettings),
		d_container(container),
		d_broken(false)
	{
		reset_http_parser();
		if (stream->have_partner())
		{
			static unsigned new_stream_id = 0;
			stream_t *partner = reinterpret_cast<stream_t *>(
					stream->partner()->userdata());
			if (partner)
				d_streamid = partner->d_streamid;
			else
				d_streamid = new_stream_id++;
		}
	}

	~stream_t()
	{
		// still partial results in buffers?
		if (d_current_request)
			d_container->add_request(d_current_request);
		if (d_current_response)
			d_container->add_response(d_current_response);
	}

	void accept_tcp(packet_t *packet, int packetloss)
	{
		if (d_broken)
			return;

		if (packet)
		{
			layer_t *toplayer = packet->layer(-1);
			if (!toplayer || toplayer->type() != layer_data)
				return;

			size_t nparsed = http_parser_execute(
					&d_parser,
					d_settings,
					(const char *)toplayer->begin(),
					toplayer->size());

			if (d_parser.upgrade)
				d_broken = true; // cannot parse this
			else if (nparsed != toplayer->size())
			{
				if (g_must_be_http)
					reset_http_parser(); // try if we can restart the next packet
				else {
					printf("failed to parse http in %s\n", 
							boost::lexical_cast<std::string>(*packet).c_str());
					d_broken = true;
				}
			}
		}
		else
		{
			size_t nparsed = http_parser_execute(
					&d_parser, d_settings, nullptr, 0);
			if (nparsed != 0)
			{
				printf("failed to parse http at end of stream in %s\n", 
						boost::lexical_cast<std::string>(*packet).c_str());
				// so we are broken. but last packet anyway
			}
		}
	}

	int on_url(const char *at, size_t length)
	{
		req()->method = (http_method)d_parser.method;
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
		return 0;
	}

	int on_body(const char *at, size_t length)
	{
		if (is_request())
		{
			req()->bodysize += length;
			if (g_capture_postdata)
				req()->body.append(at, length);
		}
		else
		{
			res()->bodysize += length;
			if (g_capture_responsedata)
				res()->body.append(at, length);
		}
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
		assert(!d_current_request && !d_current_response);
		d_current_request.reset();
		d_current_response.reset();
		return 0;
	}

	int on_message_complete()
	{
		if (is_request())
		{
			assert(!d_current_response && d_current_request);
			d_current_request->complete = true;
			d_container->add_request(d_current_request);
			d_current_request.reset();
		}
		else
		{
			assert(d_current_response && !d_current_request);
			d_current_response->complete = true;
			d_container->add_response(d_current_response);
			d_current_response.reset();
		}
		return 0;
	}
protected:
	http_parser_settings *d_settings;
	http_parser d_parser;

	unsigned d_streamid; // counter for tcp-streams. same for initiator and responder

	page_container_t *d_container;

	bool d_broken;
	std::string d_field; // for http-headers

	request_ptr d_current_request;
	response_ptr d_current_response;

	void reset_http_parser()
	{
		http_parser_init(&d_parser, HTTP_BOTH); // BOTH - parser will guess
		d_parser.data = this;
	}

	const char *cd()
	{
		switch(d_parser.type)
		{
			case(HTTP_REQUEST): return "request";
			case(HTTP_RESPONSE): return "response";
			default: return "unknown";
		}
	}

	bool is_request() const
	{
		if (d_parser.type == HTTP_REQUEST)
			return true;
		else if (d_parser.type == HTTP_RESPONSE)
			return false;
		else
			throw std::runtime_error("Don't know if data is request or response");
	}

	request_or_response_t *cur()
	{
		return is_request() ?
			static_cast<request_or_response_t *>(req()) :
			static_cast<request_or_response_t *>(res());
	}

	request_t *req()
	{
		assert(is_request());
		if (!d_current_request)
		{
			d_current_request.reset(new request_t);
			d_current_request->method = (http_method)d_parser.method;
			d_current_request->tcp_streamid = d_streamid;
		}
		return d_current_request.get();
	}

	response_t *res()
	{
		assert(!is_request());
		if (!d_current_response)
		{
			d_current_response.reset(new response_t);
			d_current_response->tcp_streamid = d_streamid;
		}
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



class burl_packet_listener_t : public packet_listener_t
{
public:
	burl_packet_listener_t(page_container_t *out) :
		d_container(out), d_packetloss(0)
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
	~burl_packet_listener_t() {}

	void begin_capture(const std::string &name, int linktype, int snaplen)
	{
	}

	void accept_tcp(packet_t *packet, int packetloss, tcp_stream_t *stream)
	{
		auto_release_t<packet_t> releaser(packet);

		// new side of a connection. we deal with both sides completely independant

		d_packetloss += packetloss;

		stream_t *user = reinterpret_cast<stream_t *>(stream->userdata());
		if (!user)
		{
			user = new stream_t(stream, &d_settings, d_container);
			stream->set_userdata(user);
		}
		if (user)
			user->accept_tcp(packet, packetloss);

		if (!packet)
		{
			delete user;
			stream->set_userdata(nullptr);
		}
	}

	void accept_error(packet_t *packet, const char *error)
	{
		throw format_exception("error parsing packet '%s': %s", to_str(*packet).c_str(), error);
	}

protected:
	http_parser_settings d_settings;
	page_container_t *d_container; // storage for the requests/responses
	uint64_t d_packetloss;
};


struct burl_t : public burl_packet_listener_t
{
	burl_t(page_container_t *container) :
		burl_packet_listener_t(container),
		d_reader(this),
		d_quit(false)
	{
		d_reader.enable_udp_reassembly(false);
	}

	~burl_t()
	{
		printf("flushing\n");
		flush();
		printf("destroying reader\n");
	}

	void read_pcap(const std::string &filename, const std::string &bpf)
	{ d_reader.read_file(filename, bpf); }

	void read_live_capture(const std::string &device, const std::string &bpf)
	{
		d_reader.open_live_capture(device, true, bpf);
		while (!d_quit)
			d_reader.read_packets();
	}

	// to stop read_live_capture. will probably not stop until next packet is received
	void quit() { d_quit = true; }

	void flush() { d_reader.flush(); }


protected:
	pcap_reader_t d_reader;
	bool d_quit;
};

struct request_response_combiner_t : public page_container_t
{
	~request_response_combiner_t()
	{
		unsigned reqcount = 0;
		for(auto it: d_requests)
			reqcount += it.second.size();
		printf("%d requests without response\n", reqcount);

		unsigned rescount = 0;
		for(auto it: d_responses)
			rescount += it.second.size();
		printf("%d responses without request\n", rescount);
	}

	void print(const request_ptr &req, const response_ptr &res)
	{
		printf("%d %s %s %s (%ld bytes postdata and %ld bytes response)\n",
				res->status,
				req->method_str(),
				req->header_first("Host", "unknownhost").c_str(),
				req->url.c_str(),
				req->bodysize,
				res->bodysize);
	}

	void add_request(const request_ptr &req)
	{
		auto res_iter = d_responses.find(req->tcp_streamid);
		if (res_iter == d_responses.end())
		{
			d_requests[req->tcp_streamid].push_back(req);
			return;
		}

		response_ptr res = res_iter->second.front();
		res_iter->second.pop_front();
		if (res_iter->second.empty())
			d_responses.erase(res_iter);

		// FIXME: found request must be before response

		print(req, res);
	}

	void add_response(const response_ptr &res)
	{
		auto req_iter = d_requests.find(res->tcp_streamid);
		if (req_iter == d_requests.end())
		{
			d_responses[res->tcp_streamid].push_back(res);
			return;
		}

		request_ptr req = req_iter->second.front();
		req_iter->second.pop_front();
		if (req_iter->second.empty())
			d_requests.erase(req_iter);

		// FIXME: found request must be before response

		print(req, res);
	}

protected:
	// requests and responses without partner
	std::unordered_map<unsigned, std::list<request_ptr>> d_requests;
	std::unordered_map<unsigned, std::list<response_ptr>> d_responses;
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

	request_response_combiner_t requests;
	burl_t burl(&requests);
	if (!live)
		for(const std::string &file: positional)
			burl.read_pcap(file, filter);
	else
	{
		std::string device = "any";
		if (!positional.empty())
			device = positional[0];
		burl.read_live_capture(device, filter);
	}
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

