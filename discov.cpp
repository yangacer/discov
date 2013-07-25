#ifdef _WIN32
#pragma warning ( disable : 4345 4819)
#endif
#include "discov.hpp"
#ifdef _WIN32
#include <Winsock2.h>
#else
#include <sys/select.h>
#endif
#include <vector>
#include <sstream>
#include <fstream>
#include <string>

#include <cerrno>
#include <cassert>

//#include <iostream>
#include "dns_sd.h"
#include "json/json.hpp"

namespace {

namespace json = yangacer::json;

struct context
{
  std::vector<DNSServiceRef> sref_list;
  std::vector<DNSServiceRef> pending_list;
  std::stringstream *sstream_ptr;
  int wait_time;

  context()
  {
    using namespace std;
    ifstream fin;
    fin.unsetf(ios::skipws);
    fin.open("known_hosts", ios::binary | ios::in);
    if(fin.is_open()) {
      json::istream_iterator beg(fin), end;
      json::phrase_parse(beg, end, known_hosts);
      fin.close();
    } else {
      known_hosts = json::object_t();
      mbof(known_hosts)["devices"] = json::array_t();
    }
  }

  ~context()
  {
    using namespace std;
    ofstream fout("known_hosts", ios::binary | ios::out | ios::trunc);
    if(fout.is_open() )
      json::pretty_print(fout, known_hosts);
    fout.flush();
    fout.close();
  }

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
  
  json::var_t known_hosts;
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

struct name_eq
{
  name_eq(std::string const &name)
    : name(name)
    {}

  bool operator()(json::var_t const &val) const
  {
    return cmbof(val)["name"].string() == name;
  }

  std::string const &name;
};

static json::object_t parse_txtrecord(unsigned char const *txt, uint16_t size)
{
  using namespace std;
  json::object_t rt;
  uint8_t pair_len = 0;
  while(size) {
    pair_len = txt[0];
    size--;
    txt++;
    uint8_t const *end = txt + pair_len;
    uint8_t const *pos = find(txt, end, 0x3du);
    if( pos == end ) {
      rt[string((char const*)txt, pair_len).c_str()] = true;
    } else {
      rt[string((char const*)txt, pos - txt).c_str()] =
        string((char const*)pos+1, end - pos - 1);
    }
    txt += pair_len;
    size -= pair_len;
  }
  return rt;
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
  json::array_t &hosts = 
    mbof(myctx->known_hosts)["devices"].array();
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
    string brief(name);
    brief = brief.substr(0, brief.find("._"));
    hosts.erase(
      remove_if(hosts.begin(), hosts.end(), name_eq(brief)),
      hosts.end());
    
      stringstream addr;
      addr << target;
      addr.seekp(-1, ios::end) << ":" << ntohs(port);
      
      json::object_t obj;
      mbof(obj["name"]) = brief;
      mbof(obj["host"]) = addr.str();
      // parse txtRecord
      auto txt = parse_txtrecord(txtRecord, txtLen);
      obj.insert(txt.begin(), txt.end());
      hosts.push_back(obj);
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
  int maxfd = 0; 
  for(auto sref_iter = ctx.sref_list.begin(); sref_iter != ctx.sref_list.end(); ++sref_iter) {
    auto fd = DNSServiceRefSockFD(*sref_iter);
    FD_SET(fd, &fds);
    if(fd > maxfd) maxfd = fd;
  }
  int active;
  struct timeval tv = { ctx.wait_time, 5000 };
  while ( 0 < (active = select(maxfd+1, &fds, 0, 0, &tv)) ) {
    assert(errno != EINVAL && "exceed nfsd size");
    maxfd = 0;
    for(auto sref_iter = ctx.sref_list.begin(); sref_iter != ctx.sref_list.end(); ++sref_iter) {
      auto fd = DNSServiceRefSockFD(*sref_iter);
      if( FD_ISSET(fd, &fds) ) {
        // Invoke callback
        DNSServiceErrorType ec = DNSServiceProcessResult(*sref_iter);
        DNSServiceRefDeallocate(*sref_iter);
        *sref_iter = 0;
        FD_CLR(fd, &fds);
      } else {
        FD_SET(fd, &fds);
        if(fd > maxfd) maxfd = fd;
      }
    } // foreach sref_list
  } // while(select)
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
    ctx.sref_list.push_back(sref);
    while(ctx.sref_list.size()) 
      do_select(ctx);
    json::pretty_print(sstream, ctx.known_hosts);
  }
}

