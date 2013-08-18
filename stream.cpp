#include "stream.h"
#include "burl_settings.h"
#include "packet_listener.h"
#include "http-parser/http_parser.h"
#include "reass/tcp_reassembler.h"

stream_t::stream_t(
		tcp_stream_t *stream,
		burl_settings_t *burlsettings,
		http_parser_settings *parsersettings,
		page_container_t *container) :
	d_burlsettings(burlsettings),
	d_httpsettings(parsersettings),
	d_container(container),
	d_broken(false)
{
	d_parser = new http_parser;
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

stream_t::~stream_t()
{
	// still partial results in buffers?
	if (d_current_request)
		d_container->add_request(d_current_request);
	if (d_current_response)
		d_container->add_response(d_current_response);

	delete d_parser;
	d_parser = nullptr;
}

void stream_t::accept_packet(packet_t *packet, int packetloss)
{
	if (d_broken)
		return;

	if (packet)
	{
		layer_t *toplayer = packet->layer(-1);
		if (!toplayer || toplayer->type() != layer_data)
			return;

		size_t nparsed = http_parser_execute(
				d_parser,
				d_httpsettings,
				(const char *)toplayer->begin(),
				toplayer->size());

		if (d_parser->upgrade)
			d_broken = true; // cannot parse this
		else if (nparsed != toplayer->size())
		{
			if (d_burlsettings->it_really_is_http)
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
				d_parser, d_httpsettings, nullptr, 0);
		if (nparsed != 0)
		{
			printf("failed to parse http at end of stream in %s\n", 
					boost::lexical_cast<std::string>(*packet).c_str());
			// so we are broken. but last packet anyway
		}
	}
}

int stream_t::on_url(const char *at, size_t length)
{
	req()->method = (http_method)d_parser->method;
	req()->url = std::string(at, length).c_str();
	return 0;
}

int stream_t::on_header_field(const char *at, size_t length)
{
	d_field.assign(at, length);
	return 0;
}

int stream_t::on_header_value(const char *at, size_t length)
{
	typedef request_or_response_t::headerpair_t headerpair_t;
	cur()->headers.push_back(
			headerpair_t(d_field, std::string(at, length)));
	return 0;
}

int stream_t::on_body(const char *at, size_t length)
{
	if (is_request())
	{
		req()->bodysize += length;
		if (d_burlsettings->capture_postdata)
			req()->body.append(at, length);
	}
	else
	{
		res()->bodysize += length;
		if (d_burlsettings->capture_responsedata)
			res()->body.append(at, length);
	}
	return 0;
}

int stream_t::on_status_complete()
{
	res()->status = d_parser->status_code;
	return 0;
}

int stream_t::on_message_begin()
{
	assert(!d_current_request && !d_current_response);
	return 0;
}

int stream_t::on_message_complete()
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


void stream_t::reset_http_parser()
{
	http_parser_init(d_parser, HTTP_BOTH); // BOTH = parser will guess
	d_parser->data = this;
}

bool stream_t::is_request() const
{
	if (d_parser->type == HTTP_REQUEST)
		return true;
	else if (d_parser->type == HTTP_RESPONSE)
		return false;
	else
		throw std::runtime_error("Don't know if data is request or response");
}

request_or_response_t *stream_t::cur()
{
	return is_request() ?
		static_cast<request_or_response_t *>(req()) :
		static_cast<request_or_response_t *>(res());
}

request_t *stream_t::req()
{
	assert(is_request());
	if (!d_current_request)
	{
		d_current_request.reset(new request_t);
		d_current_request->method = (http_method)d_parser->method;
		d_current_request->tcp_streamid = d_streamid;
	}
	return d_current_request.get();
}

response_t *stream_t::res()
{
	assert(!is_request());
	if (!d_current_response)
	{
		d_current_response.reset(new response_t);
		d_current_response->tcp_streamid = d_streamid;
	}
	return d_current_response.get();
}

