#ifdef _WIN32
#pragma warning ( disable : 4345 4819)
#endif
#include "discov.hpp"
#include <Winsock2.h>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
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
  stringstream sin(string((char const*)txt, size));
  string line;
  while(getline(sin, line, (char)0x1a)) {
    auto pos = line.find("=");
    if( pos != string::npos )
      rt[line.substr(0, pos).c_str()] = line.substr(pos+1);
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
    if( hosts.end() == find_if(hosts.begin(), hosts.end(), name_eq(brief)) ) {
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
    ctx.sref_list.push_back(sref);
    while(ctx.sref_list.size()) 
      do_select(ctx);
    json::pretty_print(sstream, ctx.known_hosts);
  }
}

