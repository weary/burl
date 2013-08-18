#ifndef __BURL_SETTINGS_H__
#define __BURL_SETTINGS_H__

struct burl_settings_t
{
	// are we interested in the postdata
	bool capture_postdata = true;

	// are we interested in the body
	bool capture_responsedata = true;

 	// if we are sure it is http. will try harder to parse http (otherwise we probably got a non-http stream and ignore on errors)
	bool it_really_is_http = false;
};

#endif // __BURL_SETTINGS_H__
