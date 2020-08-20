#include "libssh2.hpp"
#include <iostream>
#include <bitset>
#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

void SetStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

int main(int argc, char **argv)
{

    std::string username, password;
    size_t nread;
    char *ptr;
    char mem[1024];
    int rc;

    std::cout << "SCP Test" << std::endl;
    
    libssh2::session s;
    try
    {

        s.open("127.0.0.1", 22);
        libssh2::fingerprint f = s.get_host_fingerprint();
        std::cout << "SHA1 fingerprint: " << f.get_hex_sha1() << std::endl
                  << "MD5  fingerprint: " << f.get_hex_md5() << std::endl;

        std::cout << " Enter Username: ";
        std::cin >> username;

        std::cout << " Password: ";
        SetStdinEcho(false);
        std::cin >> password;
        SetStdinEcho(true);

        FILE *local = fopen("./test.txt", "rb");
            if(!local) {
                std::cerr << "Can't open local file " << "./test.txt" << std::endl;
            }

        std::cout << "Auth methods for username: " << username << " " << std::bitset<8>(s.get_auth_methods(username)) << std::endl;

        s.auth_password(username, password);
        libssh2::channel *c = s.open_scp_channel("/home/markus/test.txt", local);
        //c->request_pty();

        if (!c)
        {
            char *errmsg;
            int errlen;
            int err = libssh2_session_last_error(s.get_session_ptr(), &errmsg, &errlen, 0);

            fprintf(stderr, "Unable to open a session: (%d) %s\n", err, errmsg);
            goto shutdown;
        }

        fprintf(stderr, "SCP session waiting to send file\n");
        do
        {
            nread = fread(mem, 1, sizeof(mem), local);
            if (nread <= 0)
            {
                /* end of file */
                break;
            }
            ptr = mem;

            do
            {
                /* write the same data over and over, until error or completion */
                rc = libssh2_channel_write(c->get_channel_ptr(), ptr, nread);

                if (rc < 0)
                {
                    fprintf(stderr, "ERROR %d\n", rc);
                    break;
                }
                else
                {
                    /* rc indicates how many bytes were written this time */
                    ptr += rc;
                    nread -= rc;
                }
            } while (nread);

        } while (1);
    }
    catch (libssh2::exception e)
    {
        std::string error_msg;
        int err = s.get_session_last_error(error_msg);
        std::cerr << error_msg << " / ";
        std::cerr << e.what() << std::endl;
        
    }

shutdown:
//     fprintf(stderr, "Sending EOF\n");
//     libssh2::libssh2_channel_send_eof(c);

 
//     fprintf(stderr, "Waiting for EOF\n");
//     libssh2_channel_wait_eof(channel);

 
//     fprintf(stderr, "Waiting for channel to close\n");
//     libssh2_channel_wait_closed(channel);

 
//     libssh2_channel_free(channel);

//     channel = NULL;
 
//  shutdown:
 
//     if(session) {
//         libssh2_session_disconnect(session, "Normal Shutdown");

//         libssh2_session_free(session);

//     }
// #ifdef WIN32
//     closesocket(sock);
// #else
//     close(sock);
// #endif
//     if(local)
//         fclose(local);
//     fprintf(stderr, "all done\n");
 
//     libssh2_exit();
    return 0;
}
