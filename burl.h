#ifndef __BURL_H__
#define __BURL_H__

#include "packet_listener.h"
#include "burl_settings.h"
#include "reass/pcap_reader.h"
#include <boost/noncopyable.hpp>
#include <string>


struct burl_t : public boost::noncopyable
{
	burl_t(request_listener_t *container);
	~burl_t();

	void read_pcap(const std::string &filename, const std::string &bpf);
	void live_capture(const std::string &device, const std::string &bpf);

	// to stop read_live_capture. will probably not stop until next packet is received
	void quit() { d_quit = true; }

	void flush() { d_reader.flush(); }


protected:
	burl_settings_t d_settings;
	burl_packet_listener_t d_listener;
	pcap_reader_t d_reader;
	bool d_quit;
};

#endif // __BURL_H__
