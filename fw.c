
/*
 * CPSC 526 Assignment 5
 * Geordie Tait
 * 10013837
 * T02
 *
 * Firewall simulator
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

#define RULE_IND    globals.rules[index]
#define RULE_NR     globals.rules[globals.nRules]

#define MAXRULES    2048
#define MAXPORTS    256

#define RULELEN 1024
#define DIRLEN  4
#define ACTLEN  24
#define IPLEN   24

// data structure for rules
struct Rule {
    
    int line;                   // line number
    char dir[DIRLEN];           // direction
    char action[ACTLEN];        // action
    char ip[IPLEN];             // IP string
    unsigned long net, netmask; // IP number and netmask
    int bits;                   // CIDR bits
    int wildIP;                 // IP wildcard flag
    int ports[MAXPORTS];        // ports array
    int nPorts;                 // number of ports
    int wildPorts;              // ports wildcard flag
    int flag;                   // established flag
};

// data structure for packets
struct Packet {

    char dir[DIRLEN];   // direction
    char ipstr[IPLEN];  // IP string
    unsigned long ip;   // IP number
    int port;   // port number
    int flag;   // established flag
};

// global variables
struct {
    struct Rule rules[MAXRULES];    // array of rules
    int nRules;                     // number of rules
} globals;

/*********************************************************/
/* Utility functions */
/*********************************************************/

// report error message & exit
void die( const char * errorMessage, ...) {

    fprintf( stderr, "Error: ");
    va_list args;
    va_start( args, errorMessage);
    vfprintf( stderr, errorMessage, args);
    fprintf( stderr, "\n");
    va_end( args);
    exit(-1);
}

// print usage and exit
void usage() {
    die( "Usage: ./fw <config file path>\n");
}

// check if a string is blank
int isBlank(char *str) {
    int len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (!isspace(str[i]))
            return 0;
    }
    return 1;
}

// replace newlines with null chars
void trimnl(char *str) {
    for (int i = 0; i <= strlen(str); i++) {
        if (str[i] == '\n') {
            str[i] = 0;
        }
    }
}

/*********************************************************/
/* IP parsing and matching functions */
/*********************************************************/

// parse an IPv4 string into a number
unsigned long IPstrtol(char* ip) {

    char *p1, *p2, *p3, *p4, *end;
    int ipBytes[4];
    char ipAddress[IPLEN];
    strcpy(ipAddress, ip);

    // split on .
    p1 = strtok(ipAddress, ".");
    p2 = strtok(NULL, ".");
    p3 = strtok(NULL, ".");
    p4 = strtok(NULL, ".");

    // check if 4 pieces
    if (p1 == NULL || p2 == NULL || p3 == NULL 
            || p4 == NULL || strtok(NULL, ".") != NULL)
        return 0;
    
    // convert strings to numbers
    ipBytes[0] = strtol(p1, &end, 10);
    if (*end != 0) return 0;
    ipBytes[1] = strtol(p2, &end, 10);
    if (*end != 0) return 0;
    ipBytes[2] = strtol(p3, &end, 10);
    if (*end != 0) return 0;
    ipBytes[3] = strtol(p4, &end, 10);
    if (*end != 0) return 0;

    // shift and combine pieces and return
    return ipBytes[0] | ipBytes[1] << 8 | ipBytes[2] << 16 | ipBytes[3] << 24;
}

// check if IP matches a network and mask
int checkIPMatch(unsigned long addr, 
                 unsigned long net, 
                 unsigned long mask) {

    // bitwise and addr with netmask
    // bitwise and net with netmask
    // IP matches if the results are equal
    return ((addr & mask) == (net & mask));
}

// produce netmask for a rule using cidr bits
int generateMask(int bits, struct Rule *rule) {

    // init netmask to zero
    rule->netmask = 0;

    // check number of bits
    if (bits < 0 || bits > 32)
        return 0;

    // calculate netmask
    int oct = (bits + 7) / 8;
    if (oct > 0) {
        memset(&rule->netmask, 255, (size_t)oct - 1);
        memset((unsigned char *)&rule->netmask + (oct - 1),
               (256 - (1 << (32 - bits) % 8)), 1);
    }
    return 1;
}

int parseIP(char *ip, int num) {

    // copy ip string if not over max ip length
    if (strlen(ip) < IPLEN)
        strcpy(RULE_NR.ip, ip);
    else return 0;

    // ip is wildcard
    if (strcmp(ip, "*") == 0)
        RULE_NR.wildIP = 1;

    // ip is not wildcard
    else {

        // check and parse IP and cidr bits
        RULE_NR.wildIP = 0;
        char *net, *bitstr, *end = NULL;
        net = strtok(ip, "/");
        bitstr = strtok(NULL, "/");
        int bits = -1;
        if (bitstr != NULL)
            bits = strtol(bitstr, &end, 10);

        RULE_NR.net = IPstrtol(net);
        if (RULE_NR.net == 0) {
            fprintf(stderr, "Warning: ignored rule with invalid IP range (line %d)\n", num);
            return 0;
        }
        RULE_NR.bits = bits;
        if (!generateMask(bits, &RULE_NR)) {
            fprintf(stderr, "Warning: ignored rule with invalid CIDR bits (line %d)\n", num);
            return 0;
        }
    }
    return 1;
}

/*********************************************************/
/* Port parsing functions */
/*********************************************************/

// add a parsed port to a rule
int addPort(char *str, int index) {

    char *end = NULL;
    int port;
    int len = strlen(str);

    // trim port string and check if number or wildcard
    for (int i = 0; i < len; i++) {
        if (isdigit(str[len-i]) || str[len-i] == '*')
            break;
        else if (str[len-i] == 0)
            continue;
        else if (isspace(str[len-i]))
            str[len-i] = 0;
        else
            return 0;
    }

    // port is a number
    if (strcmp(str, "*") != 0) {

        port = strtol(str, &end, 10);
        if (*end != 0 || port < 0 || port > 65535)
            return 0;

        RULE_IND.ports[RULE_IND.nPorts] = port;
        RULE_IND.nPorts++;
    }

    // port is wildcard
    else {
        RULE_IND.nPorts = -1;
        RULE_IND.wildPorts = 1;
    }

    return 1;
}

// check and parse ports (separated by commas)
int parsePorts(char *ports, int num) {

    RULE_NR.nPorts = 0;
    RULE_NR.wildPorts = 0;
    char *p;
    
    // check the first port
    p = strtok(ports, ",");
    if (p == NULL || !addPort(p, globals.nRules)) {
        fprintf(stderr, "Warning: ignored rule with invalid port(s) (line %d)\n", num);
        return 0;
    }

    // check the rest of the ports, if any
    p = strtok(NULL, ",");
    while (p != NULL) {

        if (!addPort(p, globals.nRules)) {
            fprintf(stderr, "Warning: ignored rule with invalid port(s) (line %d)\n", num);
            return 0;
        }
        p = strtok(NULL, ",");
    }
    return 1;
}

/*********************************************************/
/* Rule parsing functions */
/*********************************************************/

// parse rule data from a line of the config file
void parseRule(char *line, int num) {

    // remove newlines
    trimnl(line);

    // trim leading spaces and skip line if comment
    for (int i = 0; i < strlen(line); i++) {
        if (isspace(line[i]))
            *line++;
        if (line[i] == '#')
            return;
        else if (line[i] > 47 && line[i] < 123)
            break;
    }

    // split line on spaces
    char *dir, *act, *ip, *ports, *flag;
    char tmp[RULELEN];
    strcpy(tmp, line);
    dir = strtok(line, " ");
    act = strtok(NULL, " ");
    ip = strtok(NULL, " ");
    ports = strtok(NULL, " ");
    flag = strtok(NULL, " ");

    // ignore rule if too many fields
    if (strtok(NULL, " ") != NULL) {
        fprintf(stderr, "Warning: ignored rule with too many fields (line %d)\n", num);
        return;
    }

    // if missing fields try to split line on tabs
    if (act == NULL || ip == NULL
            || ports == NULL) {
        
        dir = strtok(tmp, "\t");
        act = strtok(NULL, "\t");
        ip = strtok(NULL, "\t");
        ports = strtok(NULL, "\t");
        flag = strtok(NULL, "\t");

        // ignore rule if too many fields
        if (strtok(NULL, "\t") != NULL) {
            fprintf(stderr, "Warning: ignored rule with too many fields (line %d)\n", num);
            return;
        }
    }

    // skip if line is blank
    if (dir == NULL || dir[0] == 10 || isBlank(dir))
        return;
    
    // ignore rule if any required field is missing
    if (act == NULL || ip == NULL || ports == NULL) {
        fprintf(stderr, "Warning: ignored malformed rule (line %d)\n", num);
        return;
    }

    // check and set direction
    if (strcmp(dir, "in") != 0 && strcmp(dir, "out") != 0) {
        fprintf(stderr, "Warning: ignored rule with invalid direction (line %d)\n", num);
        return;
    }
    if (strlen(dir) < DIRLEN) 
        strcpy(RULE_NR.dir, dir);   

    // check and set action
    if (strcmp(act, "accept") != 0 
            && strcmp(act, "reject") != 0
            && strcmp(act, "drop") != 0) {
        fprintf(stderr, "Warning: ignored rule with invalid action (line %d)\n", num);
        return;
    }
    if (strlen(act) < ACTLEN)
        strcpy(RULE_NR.action, act);

    // check and set flag
    if (flag != NULL && strcmp(flag, "established") != 0) {
        fprintf(stderr, "Warning: ignored rule with invalid flag (line %d)\n", num);
        return;
    }
    if (flag != NULL) RULE_NR.flag = 1;
    else RULE_NR.flag = 0;

    // check and parse ip
    if (!parseIP(ip, num))
        return;
    
    // check and parse ports
    if (!parsePorts(ports, num))
        return;

    // save the rule line number
    RULE_NR.line = num;

    // increment number of rules
    globals.nRules++;
}

// load the list of rules from the config file
void loadRules(char *path) {

    FILE *fp;
    char line[1024];
    int count = 0;

    // try to open config file for reading
    fp = fopen(path, "r");
    if (fp == NULL || fp < 0)
        die("Could not read config file");

    // read rules line by line
    while (fgets(line, sizeof(line), fp) != NULL)  {
        count++;
        parseRule(line, count);
    }

    // clean up
    fclose(fp);
}

/*********************************************************/
/* Packet parsing and output generation functions */
/*********************************************************/

// use rules to determine the action for a packet
void getPacketAction(char *output, struct Packet packet) {

    char result[ACTLEN] = "", tmp[ACTLEN] = "", tmp2[ACTLEN];
    int line;

    // for each rule
    for (int index = 0; index < globals.nRules; index++) {

        // skip if direction doesn't match
        if (strcmp(RULE_IND.dir, packet.dir) != 0)
            continue;

        // skip if ip doesn't match (unless wildcard)
        if (!RULE_IND.wildIP) {
            if (!checkIPMatch(packet.ip, RULE_IND.net, RULE_IND.netmask))
                continue;
        }

        // skip if port doesn't match (unless wildcard)
        if (!RULE_IND.wildPorts) {

            int nports = RULE_IND.nPorts;
            int match = 0;
            for (int j = 0; j < nports; j++) {
                if (packet.port == RULE_IND.ports[j]) {
                    match = 1;
                    break;
                }
            }
            if (!match) continue;
        }

        // skip if rule requires established and packet is not
        if (RULE_IND.flag && !packet.flag)
            continue;

        // copy the action and rule line number
        strcpy(result, RULE_IND.action);
        line = RULE_IND.line;
        break;
    }

    // create <action>(<rule#>) part of output string
    if (strcmp(result, "") == 0)
        strcpy(result, "drop");
    else
        sprintf(tmp, "%d", line);
    sprintf(tmp2, "%s(%s)\0", result, tmp);
    strcpy(output, tmp2);
}

// process a packet string
void processPacket(char *packet) {

    // remove newlines and trim leading spaces
    trimnl(packet);
    for (int i = 0; i < strlen(packet); i++) {
        if (isspace(packet[i]))
            *packet++;
        if (packet[i] > 47 && packet[i] < 123)
            break;
    }

    // parse fields separated by spaces
    char *dir, *ip, *portstr, *flagstr;
    char p[RULELEN];
    strcpy(p, packet);
    struct Packet pkt;
    dir = strtok(packet, " ");
    ip = strtok(NULL, " ");
    portstr = strtok(NULL, " ");
    flagstr = strtok(NULL, " ");

    // if missing any fields try separating by tabs
    if (ip == NULL || portstr == NULL || flagstr == NULL) {
        dir = strtok(p, "\t");
        ip = strtok(NULL, "\t");
        portstr = strtok(NULL, "\t");
        flagstr = strtok(NULL, "\t");
    }

    // skip if blank
    if (dir == NULL || isBlank(dir))
        return;

    // check if all fields are present
    if (ip == NULL || portstr == NULL || flagstr == NULL || strtok(NULL, " ") != NULL) {
        fprintf(stderr, "Warning: ignored invalid packet - %s\n", packet);
        return;
    }

    // check direction
    if (strcmp(dir, "in") != 0 && strcmp(dir, "out") != 0) {
        fprintf(stderr, "Warning: invalid packet (bad direction) - %s\n", dir);
        return;
    }

    // parse and check port
    int port;
    char *end = NULL;
    port = strtol(portstr, &end, 10);
    if (*end != 0) {
        fprintf(stderr, "Warning: invalid packet (bad port) - %s\n", portstr);
        return;
    }

    // parse and check flag
    int flag;
    flag = strtol(flagstr, &end, 10);
    if (*end != 0 || (flag != 0 && flag != 1)) {
        fprintf(stderr, "Warning: invalid packet (bad flag) - %s\n", flagstr);
        return;
    }

    // make and fill a packet struct
    trimnl(ip);
    strcpy(pkt.dir, dir);
    strcpy(pkt.ipstr, ip);
    pkt.port = port;
    pkt.flag = flag;
    pkt.ip = IPstrtol(ip);
    if (pkt.ip == 0) {
        fprintf(stderr, "Warning: invalid packet (bad IP) - %s\n", ip);
        return;
    }

    // determine the action to take
    char action[ACTLEN];
    getPacketAction(action, pkt);

    // generate output and print to stdout
    printf("%s %s %s %d %d\n", action, dir, ip, port, flag);
}

/*********************************************************/
/* Main program function (entry point) */
/*********************************************************/

int main( int argc, char ** argv) {

    // parse command line arguments
    if (argc != 2) usage();

    // load firewall rules from config file
    loadRules(argv[1]);

    // run the firewall simulation
    // read lines from stdin
    char line[RULELEN];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        trimnl(line);
        processPacket(line);
    }

    // exit
    return 0;
}


