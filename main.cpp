#include <Winsock2.h>
#include <vector>
#include <sstream>
#include <iostream>
#include "dns_sd.h"

struct context
{
  std::vector<DNSServiceRef> sref_list;
  std::vector<DNSServiceRef> pending_list;
  
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
    cout << "{\n\"name\" : \"" << n.substr(0, n.find("._")) << "\",\n" ;
    stringstream addr;
    addr << "\"host\" : \"" << target;
    addr.seekp(-1, ios::end) << ":" << ntohs(port);
    cout << addr.str() ;
    for(uint16_t i = 0; i != txtLen; ++i)
      if(txtRecord[i] == 0x1a)
        cout << "\",\n\"";
      else if(txtRecord[i] == '=')
        cout << "\" : \"";
      else
        cout << txtRecord[i];
    cout << "\"\n},\n";
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
    struct timeval tv = { 0, 5000 };
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

int main(int argc, char **argv)
{
  using namespace std;

  if(argc < 2) {
    cout << 
      "Usage: discov <service_type>\n" << 
      "  e.g. discov _nucstcp._tcp\n"
      ;
    exit(1);
  }

  context ctx;
  DNSServiceRef sref = 0;
  DNSServiceErrorType ec = 0;

  ec = DNSServiceBrowse(&sref, 0, 0, argv[1], 0, &handle_browse, (void*)&ctx);
  
  if(!ec) {
    cout << "{\n\"devices\" : [\n";
    ctx.sref_list.push_back(sref);
    while(ctx.sref_list.size()) 
      do_select(ctx);
    cout << "{}]\n}\n";
  }

  return 0;
}
