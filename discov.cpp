#include "discov.hpp"
#include <Winsock2.h>
#include <vector>
#include <sstream>
#include <iostream>
#include "dns_sd.h"

namespace {

struct context
{
  std::vector<DNSServiceRef> sref_list;
  std::vector<DNSServiceRef> pending_list;
  std::stringstream *sstream_ptr;
  int wait_time;

  void clear()
  {
    for(auto sref_iter = sref_list.begin(); sref_iter != sref_list.end(); ++sref_iter) {
      if(*sref_iter)
        DNSServiceRefDeallocate(*sref_iter);
    }
    sref_list.clear();
  }
  
  void swap()
  {
    clear();
    sref_list.swap(pending_list);
  }
};

} // anonymous namespace

static void DNSSD_API handle_getaddr(
  DNSServiceRef sref,
  DNSServiceFlags flags,
  uint32_t infidx,
  DNSServiceErrorType ec,
  const char *name,
  const struct sockaddr *addr,
  uint32_t ttl,
  void *ctx )
{
  // do nothing, just make os cache these results
  /*
  context *myctx = (context*)ctx;
  DNSServiceRef myref = 0;
  if(!ec) {
    //sockaddr_in const *in = (sockaddr_in const *)addr;
    //char const *ip = inet_ntoa(in->sin_addr);
    //std::cout << name << ", addr: " << ip << "\n";
  }
  */
}

static void DNSSD_API handle_resolve(
  DNSServiceRef sref,
  DNSServiceFlags flags,
  uint32_t infidx,
  DNSServiceErrorType ec,
  const char *name,
  const char *target,
  uint16_t port,
  uint16_t txtLen,
  const unsigned char *txtRecord,
  void *ctx)
{
  using namespace std;

  context *myctx = (context*)ctx;
  DNSServiceRef myref = 0;
  DNSServiceErrorType myec;
  stringstream &os = *myctx->sstream_ptr;

  if(!ec) {
    myec = DNSServiceGetAddrInfo(
      &myref, 
      kDNSServiceFlagsTimeout,
      infidx,
      kDNSServiceProtocol_IPv4,
      target,
      &handle_getaddr,
      ctx);
    if(!myec) {
      myctx->pending_list.push_back(myref);
    }
    string n(name);
    os<< "{\n\"name\" : \"" << n.substr(0, n.find("._")) << "\",\n" ;
    stringstream addr;
    addr << "\"host\" : \"" << target;
    addr.seekp(-1, ios::end) << ":" << ntohs(port);
    os << addr.str() ;
    for(uint16_t i = 0; i != txtLen; ++i)
      if(txtRecord[i] == 0x1a)
        os << "\",\n\"";
      else if(txtRecord[i] == '=')
        os << "\" : \"";
      else
        os << txtRecord[i];
    os << "\"\n},\n";
  }
}

static void DNSSD_API handle_browse(
  DNSServiceRef sref,
  DNSServiceFlags flags,
  uint32_t infidx,
  DNSServiceErrorType ec,
  const char *name,
  const char *type,
  const char *domain,
  void *ctx )
{
  context *myctx = (context*)ctx;
  DNSServiceRef myref = 0;
  DNSServiceErrorType myec;

  if ( (flags & kDNSServiceFlagsAdd) && !ec ) {
    myec = DNSServiceResolve(
      &myref, 0, infidx, name, type, domain, &handle_resolve, ctx);
    if(!myec) {
      myctx->pending_list.push_back(myref);
    }
  }
}


void do_select(context &ctx)
{
  fd_set fds;
  FD_ZERO(&fds);
  
  for(auto sref_iter = ctx.sref_list.begin(); sref_iter != ctx.sref_list.end(); ++sref_iter) {
    auto fd = DNSServiceRefSockFD(*sref_iter);
    FD_SET(fd, &fds);
  }
  for(int i=0; i < 100; ++i) {
    struct timeval tv = { ctx.wait_time, 0 };
    while( 0 < select(0, &fds, 0, 0, &tv) ) {
      for(auto sref_iter = ctx.sref_list.begin(); sref_iter != ctx.sref_list.end(); ++sref_iter) {
        auto fd = DNSServiceRefSockFD(*sref_iter);
        if( FD_ISSET(fd, &fds) ) {
          // Invoke callback
          DNSServiceErrorType ec = DNSServiceProcessResult(*sref_iter);
          DNSServiceRefDeallocate(*sref_iter);
          *sref_iter = 0;
        }
      }
    }
  }
  ctx.swap();
}

void discov(std::stringstream &sstream, char const* type, int wait_time)
{
  using namespace std;

  context ctx;
  DNSServiceRef sref = 0;
  DNSServiceErrorType ec = 0;

  ctx.sstream_ptr = &sstream;
  ctx.wait_time = wait_time;

  ec = DNSServiceBrowse(&sref, 0, 0, type, 0, &handle_browse, (void*)&ctx);
  
  if(!ec) {
    sstream << "{\n\"devices\" : [\n";
    ctx.sref_list.push_back(sref);
    while(ctx.sref_list.size()) 
      do_select(ctx);
    sstream << "{}]\n}\n";
  }
}
