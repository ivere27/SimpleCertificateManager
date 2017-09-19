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
#define OPENSSL_PATH "./openssl"    // current version is 1.1.0f

#define TMP_KEY_FILE "temp.key"

using namespace std;
using namespace certificate;

// https://stackoverflow.com/questions/125828/capturing-stdout-from-a-system-command-optimally
pid_t popen2(const char *command, int * infp, int * outfp)
{
    int p_stdin[2], p_stdout[2];
    pid_t pid;

    if (pipe(p_stdin) == -1)
        return -1;

    if (pipe(p_stdout) == -1) {
        close(p_stdin[0]);
        close(p_stdin[1]);
        return -1;
    }

    pid = fork();

    if (pid < 0) {
        close(p_stdin[0]);
        close(p_stdin[1]);
        close(p_stdout[0]);
        close(p_stdout[1]);
        return pid;
    } else if (pid == 0) {
        close(p_stdin[1]);
        dup2(p_stdin[0], 0);
        close(p_stdout[0]);
        dup2(p_stdout[1], 1);
        dup2(::open("/dev/null", O_RDONLY), 2);

        /// Close all other descriptors for the safety sake.
        for (int i = 3; i < 4096; ++i) {
            ::close(i);
        }

        setsid();
        execl("/bin/sh", "sh", "-c", command, NULL);
        _exit(1);
    }

    close(p_stdin[0]);
    close(p_stdout[1]);

    if (infp == NULL) {
        close(p_stdin[1]);
    } else {
        *infp = p_stdin[1];
    }

    if (outfp == NULL) {
        close(p_stdout[0]);
    } else {
        *outfp = p_stdout[0];
    }

    return pid;
}


TEST_CASE( "key generatation", "[new key basic]" ) {
  // minimum bit 16
  {
    int kbit = 16;
    bool keyGenerated = false;
    try {
      Key key = Key(kbit);
      keyGenerated = true;
    }catch(std::exception const& e) {}

    REQUIRE( keyGenerated == true );
  }

  {
    int kbit = 1024;
    bool keyGenerated = false;
    try {
      Key key = Key(kbit);
      keyGenerated = true;
    }catch(std::exception const& e) {}

    REQUIRE( keyGenerated == true );
  }

  {
    int kbit = 2048;
    bool keyGenerated = false;
    try {
      Key key = Key(kbit);

      if (key.getPrivateKeyString().find("-----BEGIN PRIVATE KEY-----") == 0)
        keyGenerated = true;
    }catch(std::exception const& e) {}

    REQUIRE( keyGenerated == true );
  }
}


TEST_CASE( "key generatation verification", "[new key verification]" ) {
  {
    int kbit = 1024;
    bool keyVerified = false;
    try {
      Key key = Key(kbit);

      remove(TMP_KEY_FILE);
      ofstream f(TMP_KEY_FILE);
      if (f.is_open()) {
        f << key.getPrivateKeyString();
        f.close();
      }

      const char* cmd = OPENSSL_PATH" rsa -in " TMP_KEY_FILE " -text -noout";
      int child_stdout = -1;
      pid_t child_pid = popen2(cmd, 0, &child_stdout);
      if (!child_pid)
        assert(false);

      char buf1[MAX_BUF];
      ssize_t bytes_read = read(child_stdout, buf1, sizeof(buf1));

      char buf2[MAX_BUF];
      sprintf(buf2, "Private-Key: (%d bit)", kbit);

      if (string(buf1).find(buf2) == 0)
        keyVerified = true;
    }catch(std::exception const& e) {}

    REQUIRE( keyVerified == true );
  }

}