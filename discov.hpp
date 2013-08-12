#ifndef DISCOV_HPP_
#define DISCOV_HPP_

#include <sstream>

/** Discover services via mDNS.
 * @param sstream Results formated as JSON.
 * @param type Service type such as '_http._tcp'.
 * @param wait_time Timeout when waitting for mDNS response.
 * @param prefix Prefix for saving know_host.
 */
void discov(std::stringstream &sstream, char const *type, int wait_time = 2, char const *prefix = ".");

#endif
