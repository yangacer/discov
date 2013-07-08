#include <sstream>
#include <iostream>
#include "discov.hpp"

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

  stringstream ss;

  discov(ss, argv[1], 2);

  cout << ss.str() << "\n";

  return 0;
}
