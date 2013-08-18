#include "request_response.h"
#include "http-parser/http_parser.h"

const char *request_t::method_str() const
{
	return ::http_method_str((http_method)method);
}

std::string request_or_response_t::header_first(const std::string &key, const std::string default_)
{
	for(const headerpair_t &pair: headers)
		if (pair.first == key)
			return pair.second;
	return default_;
}
