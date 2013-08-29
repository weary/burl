//#include "shared/misc.h"
//#include "reass/packet.h"
//#include "reass/pcap_reader.h"
//#include "http-parser/http_parser.h"
//#include <unordered_map>
//#include <string>
//#include <string.h>
//#include <iostream>
//#include <list>
//#include "packet_listener.h"
#include "burl.h"

burl_t::burl_t(request_listener_t *container) :
	d_listener(&d_settings, container),
	d_reader(&d_listener),
	d_quit(false)
{
	d_reader.enable_udp_reassembly(false);
}

burl_t::~burl_t()
{
	flush();
}

void burl_t::read_pcap(const std::string &filename, const std::string &bpf)
{
	d_reader.read_file(filename, bpf);
}

void burl_t::live_capture(const std::string &device, const std::string &bpf)
{
	d_reader.open_live_capture(device, true, bpf);
	while (!d_quit)
		d_reader.read_packets();
}


