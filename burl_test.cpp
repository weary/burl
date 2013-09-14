#include "burl.h"
#include <unordered_map>
#include <list>
#include <boost/algorithm/string/join.hpp>
#include "shared/misc.h"

inline bool operator >(const timeval &l, const timeval &r)
{
	if (l.tv_sec > r.tv_sec)
		return true;
	else if (l.tv_sec < r.tv_sec)
		return false;
	return l.tv_usec > r.tv_usec;
}

struct request_response_combiner_t : public request_listener_t
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
		std::vector<std::string> extra;
		if (req)
		{
			if (req->bodysize)
				extra.push_back(to_str(req->bodysize) + " bytes postdata");
			if (!req->complete)
				extra.push_back("request not complete");
			else if (!req->tcp_stream_ok && (!res || res->tcp_stream_ok))
				extra.push_back("packetloss in request stream");
		}
		else
			extra.push_back("request missing");

		if (res)
		{
			extra.push_back(to_str(res->bodysize) + " bytes response");
			if (!res->complete)
				extra.push_back("response not complete");
			else if (!res->tcp_stream_ok && (!req || req->tcp_stream_ok))
				extra.push_back("packetloss in response stream");
		}
		else
			extra.push_back("response missing");

		if (res && req && !res->tcp_stream_ok && !req->tcp_stream_ok)
			extra.push_back("packetloss in request and response stream");

		printf("%d %s %s %s (%s)\n",
				(res ? res->status : 0),
				(req ? req->method_str() : "?"),
				(req ? req->header_first("Host", "unknownhost").c_str() : ""),
				(req ? req->url.c_str() : ""),
				boost::algorithm::join(extra, ", ").c_str());
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

		if (req->timestamp > res->timestamp)  // request after response. rejecting response
		{
			print(nullptr, res);
			add_request(req);
			return;
		}


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
		burl.live_capture(device, filter);
	}
}
catch(const std::exception &e)
{
	fprintf(stderr, "EXCEPTION: %s\n", e.what());
	return -1;
}

