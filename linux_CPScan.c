#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>

#define DEFAULT_TERMINAL_COLOUR "\033[0m"

typedef enum bool {
    false,
    true
} bool;

typedef enum protocol {
    tcp,
    udp
} protocol;

typedef enum colour {           // Enum for selecting different colour codes.
    grey,
    blue,
    green,
    lightBlue,
    red,
    purple,
    orange,
    white
} colour;

// Default constants.
const size_t DEFAULT_TIMEOUT = 50;
const size_t DEFAULT_START_PORT = 1;
const size_t DEFAULT_END_PORT = 1024;
const size_t MAX_PORT = 65535;
const char *VERSION = "0.0.2";
const char *AUTHOR = "liquidlegs";

// An array of colour codes.
const char *colours[] = {
    "\x1B[1;30m", "\x1B[1;34m", "\x1B[1;32m", 
    "\x1B[1;36m", "\x1B[1;31m", "\x1B[1;35m", 
    "\x1B[1;33m", "\x1B[1;37m"
};

typedef struct PACKET_CONTENTS {
    char *ipAddress;
    unsigned short port;
    protocol pt;
    bool debug;
    long timeout;
} PACKET_CONTENTS, *PPACKET_CONTENTS;

// Forward declarations.
void ShowSyntax();
size_t SendSynPacket(PPACKET_CONTENTS config);
void ResolveDnsAddress(char *dnsQuery, char output[32]);
void ScanTarget(size_t portStart, size_t portEnd, char *domain, protocol pt, bool debug, size_t timeout);
bool arePortsCorrect(size_t arg1, size_t arg2);

/*
Function returns a colours codes as selected by the user.
Params:
    colour c        -       [The colour code.]
Returns const char*
*/
const char *clr(colour c) {
    if(c == grey) return colours[0];
    else if(c == blue) return colours[1];
    else if(c == green) return colours[2];
    else if(c == lightBlue) return colours[3];
    else if(c == red) return colours[4];
    else if(c == purple) return colours[5];
    else if(c == orange) return colours[6];
    else if(c == white) return colours[7];
    else return "";
}

/*
Function will attempt to connect to a server socket in hope that it may responnd.
Params:
    PPACKET_CONTENTS config     -       [Contains info to be sent on the socket.]
Returns size_t.
*/
size_t SendSynPacket(PPACKET_CONTENTS config) {
    size_t stream = SOCK_STREAM;                                    // Tcp stream.
    int protocol = IPPROTO_TCP;                                     // Tcp protocol.

    if(config->pt == udp) {                                         // If the udp enum is found on the config param.
        stream = SOCK_DGRAM;                                        // then set the socket to use Udp.
        protocol = IPPROTO_UDP;
    }

    struct sockaddr_in server;                                      // Destination host information.
    server.sin_addr.s_addr = inet_addr(config->ipAddress);          // Ipaddress as network byte order.
    server.sin_family = AF_INET;                                    // Uses Ipv4.
    server.sin_port = htons(config->port);                          // Server port in network byte order.

    int s = socket(AF_INET, stream, protocol);                      // Create the socket.
    if(s < 0) {
        printf("%s%s%s", clr(red), "INVALID SOCKET\n", DEFAULT_TERMINAL_COLOUR);
        return 1;
    }

    int err = fcntl(s, F_SETFL, O_NONBLOCK);                            // Sets socket to non blocking mode.
    if(err < 0) {
        printf("Unable to set socket to non blocking mode\n");
        return 1;
    }

    err = connect(s, (struct sockaddr*)&server, sizeof(server));        // Attempt to connect to server.  
    if(err < 0) {                           
        if(errno == EINPROGRESS) {                                      // Connecting is in progress.
            fd_set w, e;
            FD_ZERO(&w);
            FD_ZERO(&e);
            FD_SET(s, &w);                                              // Allow socket to written to.
            FD_SET(s, &e);                                              // Tells socket how to handle the connection if it fails.

            struct timeval timeout = {0};                               // Setup timeout period for scanning ports.
            timeout.tv_sec = 0;
            timeout.tv_usec = config->timeout*1000;                     // timeout is equal to microseconds*1000.

            select(s, NULL, &w, &e, &timeout);
            size_t counter = 0;                                         // Counts how many times the connect function is called.
            size_t time = 0;                                            // Controls how many times the connect function can be called before it moves on.
            while(errno != EISCONN && time < 2) {                       // Keep trying to connect.
                err = connect(s, (struct sockaddr*)&server, sizeof(server));
                counter++;
                if(counter >= 10) {
                    time++;
                    counter = 0;
                }
            }

            if(errno == EISCONN) {
                printf("%sOPEN [%hu]%s\n", clr(green), config->port, DEFAULT_TERMINAL_COLOUR);
                return 0;                                               // Return status success.
            }
            else if(errno != EISCONN && time >= 1) {
                if(config->debug == true) printf("%sCLOSED [%hu]%s\n", clr(red), config->port, DEFAULT_TERMINAL_COLOUR);
                return 1;                                               // Return status fail.
            }
        }
    }

    return 0;
}

/*
Function resolves dns domain names to ip addresses.
Params:
    char *dnsQuery      -       [The name of the domain you wish to query.]
    char output[32]     -       [The buffer that stores the ip address.]
Returns nothing.
*/
void ResolveDnsAddress(char *dnsQuery, char output[32]) {
    struct hostent *host = NULL;                                // Structure holds the ip address info.
	struct in_addr **addr = NULL;                           // Structures stores the ip address in its network byte order.
		
	host = gethostbyname(dnsQuery);                         // Queries the domain for ip address info.
    if(host) {
	    addr = (struct in_addr **)host->h_addr_list;        // Grab the ip address.
        strcat(output, inet_ntoa(*addr[0]));                    // Fill the output buffer.
    }
    else {
        printf("%s[%s]%s\n", clr(red), "Domain is empty.", DEFAULT_TERMINAL_COLOUR);
        exit(1);
    }
}

/*
Function displays the help menu.
Params:
    None.
Returns nothing.
*/
void ShowSyntax() {
    printf(
            "  \n"
            "  \x1B[1;36m           8  .o88b. d8888b. .d8888.  .o88b.  .d8b.  d8b   db 8\n"
            "  \x1B[1;36m           8 d8P  Y8 88  `8D 88'  YP d8P  Y8 d8' `8b 888o  88 8\n"
            "  \x1B[1;36m           8 8P      88oodD' `8bo.   8P      88ooo88 88V8o 88 8\n"
            "  \x1B[1;36m    C8888D   8b      88~~~     `Y8b. 8b      88~~~88 88 V8o88   C8888D\n"
            "  \x1B[1;36m           8 Y8b  d8 88      db   8D Y8b  d8 88   88 88  V888 8\n"
            "  \x1B[1;36m           8  `Y88P' 88      `8888Y'  `Y88P' YP   YP VP   V8P 8\n\n"
            "  \x1B[1;32m           Author:  [%s]\n"
            "  \x1B[1;32m           Version: [%s]\n\n\x1B[1;33m"
            "  ___________________________________Help___________________________________\n\n"
            "             [ -p      ]              <Scan ports within a range>\n"
            "             [ -proto  ]              <The protocol you want to use>\n"
            "             [ -dbg    ]              <Show debug information>\n"
            "             [ -t      ]              <Set syn request timeout in ms>\n"
            "             [ -h      ]              <Show this menu>\n\n"
            "             [Examples]\n"
            "                stackmypancakes.com -proto tcp -p 1 1024\n"
            "                doogle.com -dbg -proto udp -p 22 65535\n"
            "                asdf.com -t 200 -proto tcp -p 440 450\n"
            "                friendface.com -t 50 -dbg -p 50 100 -proto tcp\n"
            "  __________________________________________________________________________\n\n",
            AUTHOR, VERSION
    );
}

/*
Function runs the main loop for scanning and preparing ports to be scanned.
Params:
    size_t      portStart        -       [The start range to begin the port scan.]
    size_t      portEnd          -       [The end range to finish the port scan.]
    char        *domain          -       [The domain name to be resolved.]
    protocol    pt               -       [The protocol to use in the scan. tcp/udp.]
    bool        debug            -       [Displays debug information such as closed ports]
    long        timeout          -       [The maxium amount of time a port should be scanned before moving on to the next.]
Returns nothing.
*/
void ScanTarget(size_t portStart, size_t portEnd, char *domain, protocol pt, bool debug, size_t timeout) {
    PACKET_CONTENTS p;                                                          // Holds packet information to be sent on the socket.
    char dnsBuf[32] = {0};                                                      // Holds the ip address.
    if(debug == true) printf("%s[%s]%s\n", clr(orange), "Resolving domain name", DEFAULT_TERMINAL_COLOUR); 
    ResolveDnsAddress(domain, dnsBuf);                                          // Resolves dns name to ip address.
    p.ipAddress = dnsBuf;                                                       // Fills structure with ip address.
    
    if(debug == true) printf("%s[%s] -> %s[%s]%s\n", clr(orange), domain, clr(lightBlue), dnsBuf, DEFAULT_TERMINAL_COLOUR);
    if(timeout <= 30) p.timeout = DEFAULT_TIMEOUT;
    
    p.pt = pt;
    p.debug = debug;
    p.timeout = timeout;
    for(unsigned int index = portStart; index <= portEnd; index ++) {                           // Scan ports with in set port range.
        p.port = index;                                                                         // The port.
        size_t err = SendSynPacket(&p);                                                         // Send syn packets to each port.
        if(debug == true) printf("%sSendPacket Status [%lu]%s\n", clr(grey), err, DEFAULT_TERMINAL_COLOUR);
    }
}

/*
Function checks if the port range makes sense.
Params:
    size_t arg1     -       [The starting port range.]
    size_t arg2     -       [The ending port range.]
Returns BOOL.
*/
bool arePortsCorrect(size_t arg1, size_t arg2) {
    if(arg1 > arg2) printf("%s[StartPort (%lu) cannot be greater than EndPort (%lu)]%s\n", clr(red), arg1, arg2, DEFAULT_TERMINAL_COLOUR);
    else if(arg2 < arg1) printf("%s[StartPort (%lu) cannot be less than EndPort (%lu)]%s\n", clr(red), arg2, arg1, DEFAULT_TERMINAL_COLOUR);
    else if(arg2 > 65535) printf("%s[EndPort (%lu) You may not scan ports greater than %lu]%s\n", clr(red), arg2, MAX_PORT, DEFAULT_TERMINAL_COLOUR);
    else if(arg1 <= arg2 && arg2 >= arg1) return true;
    return false;
}

int main(int argc, char *argv[]) {
    long timeout_arg = DEFAULT_TIMEOUT;                                          // The default timeout value.
    size_t startPt = DEFAULT_START_PORT;                                         // The default start port.
    size_t endPt = DEFAULT_END_PORT;                                             // The default end port.
    bool ports = false;                                                          // Controls whether the port scan will begin.
    
    if(argc <= 1) ShowSyntax();
    else if(argc == 2) {
        if(strlen(argv[1]) > 0 && strcasecmp("-h", argv[1]) == 0) ShowSyntax();
        else if(strlen(argv[1]) > 0 && strcasecmp("-h", argv[1]) != 0) {
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], tcp, false, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 3) {
        if(strcasecmp("-dbg", argv[2]) == 0) {
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], tcp, true, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 4) {
        if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0) {
            timeout_arg = atol(argv[3]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], tcp, true, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 5) {
        if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-dbg", argv[4]) == 0) {
            timeout_arg = atol(argv[3]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], tcp, true, timeout_arg);
        }
        else if(strcasecmp("-dbg", argv[2]) == 0 && strcasecmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0) {
            timeout_arg = atol(argv[4]);
            ScanTarget(DEFAULT_START_PORT, DEFAULT_END_PORT, argv[1], tcp, true, timeout_arg);
        }
        else if(strcasecmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 6) {
        if(strcasecmp("-dbg", argv[2]) == 0 && strcasecmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, DEFAULT_TIMEOUT);
        }
        else ShowSyntax();
    }
    else if(argc == 7) {
        if(strcasecmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0 && strcasecmp("-proto", argv[5]) == 0 && strcasecmp("tcp", argv[6]) == 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, DEFAULT_TIMEOUT);
        }
        else if(strcasecmp("-p", argv[2]) == 0 && strlen(argv[3]) > 0 && strlen(argv[4]) > 0 && strcasecmp("-proto", argv[5]) == 0 && strcasecmp("udp", argv[6]) == 0) {
            startPt = atoll(argv[3]);
            endPt = atoll(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], udp, true, DEFAULT_TIMEOUT);
        }
        else if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 8) {
        if(strcasecmp("-dbg", argv[2]) && strcasecmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0 && strcasecmp("-proto", argv[6]) == 0 && 
        strcasecmp("tcp", argv[7]) == 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, DEFAULT_TIMEOUT);
        }
        else if(strcasecmp("-dbg", argv[2]) && strcasecmp("-p", argv[3]) == 0 && strlen(argv[4]) > 0 && strlen(argv[5]) > 0 && strcasecmp("-proto", argv[6]) == 0 && 
        strcasecmp("udp", argv[7]) == 0) {
            startPt = atoll(argv[4]);
            endPt = atoll(argv[5]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], udp, true, DEFAULT_TIMEOUT);
        }
        else if(strcasecmp("-dbg", argv[2]) == 0 && strcasecmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 &&
        strlen(argv[7]) > 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, timeout_arg);
        }
        else if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-dbg", argv[4]) == 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 &&
        strlen(argv[7]) > 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 9) {
        if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0 && strcasecmp("-proto", argv[7]) == 0 && 
        strcasecmp("tcp", argv[8]) == 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, false, timeout_arg);
        }
        else if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-p", argv[4]) == 0 && strlen(argv[5]) > 0 && strlen(argv[6]) > 0 && strcasecmp("-proto", argv[7]) == 0 && 
        strcasecmp("udp", argv[8]) == 0) {
            startPt = atoll(argv[5]);
            endPt = atoll(argv[6]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], udp, false, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc == 10) {
        if(strcasecmp("-dbg", argv[2]) == 0 && strcasecmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        strcasecmp("-proto", argv[8]) == 0 && strcasecmp("tcp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, timeout_arg);
        }
        else if(strcasecmp("-dbg", argv[2]) == 0 && strcasecmp("-t", argv[3]) == 0 && strlen(argv[4]) > 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        strcasecmp("-proto", argv[8]) == 0 && strcasecmp("udp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[4]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], udp, true, timeout_arg);
        }
        else if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-dbg", argv[4]) == 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        strcasecmp("-proto", argv[8]) == 0 && strcasecmp("tcp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], tcp, true, timeout_arg);
        }
        else if(strcasecmp("-t", argv[2]) == 0 && strlen(argv[3]) > 0 && strcasecmp("-dbg", argv[4]) == 0 && strcasecmp("-p", argv[5]) == 0 && strlen(argv[6]) > 0 && strlen(argv[7]) > 0 &&
        strcasecmp("-proto", argv[8]) == 0 && strcasecmp("udp", argv[9]) == 0) {
            startPt = atoll(argv[6]);
            endPt = atoll(argv[7]);
            timeout_arg = atol(argv[3]);
            ports = arePortsCorrect(startPt, endPt);
            if(ports == true) ScanTarget(startPt, endPt, argv[1], udp, true, timeout_arg);
        }
        else ShowSyntax();
    }
    else if(argc > 10) ShowSyntax();

    return 0;
}
