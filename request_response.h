#ifndef __BURL_REQUEST_RESPONSE_H__
#define __BURL_REQUEST_RESPONSE_H__

#include <memory>
#include <string>
#include <vector>

// common data for requests and responses
struct request_or_response_t
{
	request_or_response_t(const struct timeval &tv, unsigned streamid) :
		timestamp(tv), bodysize(0), tcp_streamid(streamid), complete(false)
		{}

	std::string header_first(const std::string &key, const std::string default_=std::string());

	typedef std::pair<std::string, std::string> headerpair_t;
	struct timeval timestamp;
	std::vector<headerpair_t> headers;
	std::string body;
	uint64_t bodysize; // if we don't capture the body, at least store the size
	unsigned tcp_streamid;
	bool tcp_stream_ok; // was the stream we got this from complete
	bool complete; // is this message complete (but if tcpstream is borked we might miss it's partner)
};


struct request_t : public request_or_response_t
{
	request_t(const struct timeval &tv, unsigned streamid, char method_) :
		request_or_response_t(tv, streamid), method(method_)
	{}

	const char *method_str() const;

	char method;
	std::string url;
};
typedef std::shared_ptr<request_t> request_ptr;


struct response_t : public request_or_response_t
{
	response_t(const struct timeval &tv, unsigned streamid) :
		request_or_response_t(tv, streamid),
		status(0)
	{}

	int status;
};
typedef std::shared_ptr<response_t> response_ptr;



#endif // __BURL_REQUEST_RESPONSE_H__
