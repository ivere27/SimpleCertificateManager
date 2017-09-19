#define CATCH_CONFIG_MAIN
#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>

#include "catch.hpp"
#include "SimpleCertificateManager.hpp"

#define MAX_BUF (1024*1024)

using namespace std;
using namespace certificate;

TEST_CASE( "key generatation", "[new key]" ) {
  {
    bool flag = false;
    try {
      Key key = Key(512);
      flag = true;
    }catch(std::exception const& e) {
    }
    REQUIRE( flag == true );
  }

}