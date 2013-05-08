
#include "libssh2.hpp"
#include <iostream>

int main(int argc, char **argv) {
    std::cout << "Hello, world!" << std::endl;
    try
    {
        libssh2::session s;
        s.open("127.0.0.1", 8989);
        libssh2::fingerprint f = s.get_host_fingerprint();
        std::cout << "SHA1 fingerprint: " << f.get_hex_sha1() << std::endl
            << "MD5  fingerprint: " << f.get_hex_md5() << std::endl;
            
        std::cout << "Auth methods for ruben: " << int(s.get_auth_methods("ruben")) << std::endl;
        
        s.auth_password("user","password");
        libssh2::channel* c = s.open_channel();
        c->request_pty();
    }
    catch(libssh2::exception e)
    {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
