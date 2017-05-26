#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <regex.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>


#define MASK_MAX_BITS 32
#define PREFIXES 23
#define OCTET_SIZE 8
#define OCTET_DIGIT_SIZE 3
#define SUBNETMASK_SIZE 12
#define SUBNETMASK_DOTS 3
#define OCTETS 4
#define RANGE_DASH 3
#define BUFFER_INPUT 1024
#define CIDR_DIGITS 2
#define HIGH_CIDR_RANGE 30
#define LOW_CIDR_RANGE 8

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define BOLD_RED     "\033[1m\033[31m"
#define BOLD_GREEN   "\x1b[1m\x1b[32m"
#define BOLD_YELLOW  "\x1b[1m\x1b[33m"
#define BOLD_BLUE    "\x1b[1m\x1b[34m"
#define RESET_COLOR "\x1B[0m"

typedef enum {CLASS_A = 8, CLASS_B = 16, CLASS_C = 24} networkClass;
typedef enum {PRETTY, XML, JSON} printStyle;

typedef struct
{
    char binary[MASK_MAX_BITS+1];
    char mask[SUBNETMASK_SIZE+SUBNETMASK_DOTS+1];
    networkClass class;
    int hosts;
    int cidr;
}subnetMasksInfo;

void parseIP(char *input, char ip[], char cidr[]);
char* parseUserInput(int argc, char **arg);
void getIPInfo(char *ip, char *cidr, printStyle howToPrint, int countOfIPs, int currentIP, int batch);
void prettyPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range );
void xmlPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range, int countOfIPs, int currentIP );
void jsonPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range, int countOfIPs, int currentIP );
void printCIDR();
void createMaskArray(subnetMasksInfo masks[]);
subnetMasksInfo findMaskInfo(int cidr);
char* findCIDR(char *subnetMask);
void findNetworkAddress(char networkAddress[], char *ip, char *mask);
void findBroadcastAddress(char broadcastAddress[], char *hostAddress, int cidr);
void getIPRange(char range[], char *broadcastAddress, char *networkAddress);
char* stripLastOctetOff(char address[]);
int getLastOctet(char ip[]);
void convertBinarytoIP(char ip[], char *binaryIP);
void convertIPtoBinary(char binaryIP[], char *ip);
char* convertIntToChar(int num);
char* decToBinary(int dec, int bits);
int binaryToDec(char *binary, int arrayCount, int bitsToSkip);
bool isValidIpAddress(char *ipAddress);
char *trimWhiteSpace(char *str);
void printHelp();

subnetMasksInfo subnetMasks[PREFIXES+1];





int main(int argc, char **argv)
{
    char *ip = malloc(sizeof *ip *(SUBNETMASK_SIZE+SUBNETMASK_DOTS+1));
    char *cidr = malloc(sizeof *cidr *(CIDR_DIGITS+1));

    printStyle howToPrint = PRETTY;

    extern char *optarg;
    extern int optind;
    int c;

    createMaskArray(subnetMasks);

    while (optind < argc) {
        if ((c = getopt(argc, argv, "xjch")) != -1)
        {
            switch (c) {
                case 'c':
                    printCIDR();
                    break;
                case 'h':
                    printHelp();
                    break;
                case 'x':
                    howToPrint = XML;
                    break;
                case 'j':
                    howToPrint = JSON;
                    break;
            }
        }
        else
        {
            optind++;
        }
    }

    // Data was piped into the application
    if(!isatty(STDIN_FILENO))
    {
        char (*ips)[BUFFER_INPUT] = NULL;
        int ipCount = 0;

        ips = malloc (BUFFER_INPUT * sizeof *ips);

        while (fgets (ips[ipCount], BUFFER_INPUT, stdin))
        {
            char *line = ips[ipCount];
            for (; *line && *line != '\n'; line++) {}
            *line = 0, ipCount++;
        }

        for (int i = 0; i < ipCount; i++)
        {
            parseIP(ips[i], ip, cidr);
            getIPInfo(ip, cidr, howToPrint, ipCount , i+1, 1);
        }
    }
    else // Data was not piped
    {
        if ( argc > 1 )
        {
            char *input = parseUserInput(argc, argv);

            parseIP(input, ip, cidr);

            getIPInfo(ip, cidr, howToPrint, 1 , 1, 0);
        }
    }

    return 0;
}

char* parseUserInput(int argc, char **arg)
{
    int amountOfArgs = 0; 
    for (int i = 0; i < argc-1; i++)
    {
        amountOfArgs++;
    }

    int charSize = 0;
    for (int i = 1; i <= amountOfArgs; i++)
    {
        charSize += strlen(arg[i]);
    }

    char *combinedInput = malloc(sizeof *combinedInput *(amountOfArgs+charSize));

    for (int i = 1; i <= amountOfArgs; i++)
    {
        if ((strncmp(arg[i], "-j", strlen(arg[i])) != 0) && (strncmp(arg[i], "-x", strlen(arg[i])) != 0))
            strcat(combinedInput, arg[i]);

        if (i != amountOfArgs)
            strcat(combinedInput, " ");
    }

    return trimWhiteSpace(combinedInput);
}
// Test the input IP to see what format it's in. If the IP is in 192.168.0.0/24 or it will assume 192.168.0.0 255.255.255.0 and deal with the error
void parseIP(char *input, char ip[], char cidr[])
{
    regex_t regexCompiled;

    char * regexIPandCIDR = "^([0-9]{1,3}.){3}[0-9]{1,3}(/([0-9]|[0-9][0-9]))$";
    regcomp(&regexCompiled, regexIPandCIDR, REG_EXTENDED);

    // Tests if the input string looks like ip/two digits. Doesn't matter that it doesn't check for correct CIDR, that error correction comes later.
    if (regexec(&regexCompiled, input, 0, NULL, 0))
    {
        // This will test if you have two IPs next to each other with a space. Doesn't matter that it doesn't checks for correct subnetmask, that error correction comes later
        char * regexIPandMask = "^([0-9]{1,3}.){3}[0-9]{1,3}( ([0-9]{1,3}.){3}[0-9]{1,3})$";
        regcomp(&regexCompiled, regexIPandMask, REG_EXTENDED);
        if (!regexec(&regexCompiled, input, 0, NULL, 0))
        {
            char *subnetMask = malloc(sizeof *input *((SUBNETMASK_SIZE+SUBNETMASK_DOTS)+1));

            char *space = " ";
            // Breaks the ip and the mask apart
            strcpy(ip, strtok(input, space));
            strcpy(subnetMask, strtok(NULL, space));
            strcpy(cidr, findCIDR(subnetMask));
        }
    }
    else
    {
        // Breaks the cidr off of the ip
        char *slash = "/";
        strcpy(ip, strtok(input, slash));
        strcpy(cidr, strtok(NULL, slash));
    }

    regfree(&regexCompiled);
}

void getIPInfo(char *ip, char *cidr, printStyle howToPrint, int countOfIPs, int currentIP, int batch)
{
    if (isValidIpAddress(ip) && cidr != NULL)
    {
        //Valid IP
        int cidrInt = atoi( cidr );

        if (cidrInt >= LOW_CIDR_RANGE && cidrInt <= HIGH_CIDR_RANGE)
        {
            subnetMasksInfo maskInfo = findMaskInfo(cidrInt);

            char *networkAddress = malloc(sizeof *networkAddress *(SUBNETMASK_SIZE+SUBNETMASK_DOTS+1));
            findNetworkAddress(networkAddress,ip,maskInfo.binary);

            char *broadcastAddress = malloc(sizeof *broadcastAddress *(SUBNETMASK_SIZE+SUBNETMASK_DOTS+1));
            findBroadcastAddress(broadcastAddress, ip ,maskInfo.cidr);

            char *range = malloc(sizeof *range *(((SUBNETMASK_SIZE+SUBNETMASK_DOTS)*2)+RANGE_DASH+1));

            getIPRange(range, broadcastAddress, networkAddress);

            if (howToPrint == XML)
                xmlPrintResults(ip, maskInfo,networkAddress,broadcastAddress,range, countOfIPs , currentIP);
            else if (howToPrint == JSON)
                jsonPrintResults(ip, maskInfo,networkAddress,broadcastAddress,range, countOfIPs , currentIP);
            else
                prettyPrintResults(ip, maskInfo,networkAddress,broadcastAddress,range);
        }
        else
        {
            if (batch != 1)
            {
                printf("%d is not a valid cidr value. Please enter a cidr value between %d and %d\n",cidrInt,LOW_CIDR_RANGE,HIGH_CIDR_RANGE);
                printHelp();
            }
        }
    }
    else
    {
        if (batch != 1)
        {
            printf("Please enter a valid IP address\n");
            printHelp();
        }
    }
}

void prettyPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range )
{
    printf("\n------------------  IP Address Info  ------------------\n");
    printf("| %-26s %24s |\n", "IP Address", ip);
    printf("| %-26s %24s |\n", "Subnet Mask", maskInfo.mask);
    printf("| %-26s %24d |\n", "CIDR", maskInfo.cidr);
    printf("| %-26s %24s |\n", "Network Address",networkAddress);
    printf("| %-26s %24s |\n", "Broadcast Address",broadcastAddress);
    printf("| %-17s %33s |\n", "Range", range);
    printf("| %-26s %24d |\n", "Number of hosts", maskInfo.hosts);
    printf("-------------------------------------------------------\n\n");
}

void xmlPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range, int countOfIPs, int currentIP )
{
    if (currentIP == 1)
        printf("<?xml version=\"1.0\"?>\n<root>\n");

    printf("<ip>%s\n", ip);
    printf("<subnetmask>%s</subnetmask>\n",maskInfo.mask);
    printf("<cidr>%d</cidr>\n",maskInfo.cidr);
    printf("<networkaddress>%s</networkaddress>\n",networkAddress);
    printf("<broadcastaddress>%s</broadcastaddress>\n",broadcastAddress);
    printf("<range>%s</range>\n",range);
    printf("<hosts>%d</hosts>\n",maskInfo.hosts);
    printf("</ip>\n");

    if (countOfIPs == currentIP)
        printf("</root>\n");
}

void jsonPrintResults(char *ip, subnetMasksInfo maskInfo, char *networkAddress, char *broadcastAddress, char *range, int countOfIPs, int currentIP )
{
    if (currentIP == 1)
        printf("[");

    printf("\n{\n \"ip\":\"%s\",\n", ip);
    printf(" \"subnetmask\":\"%s\",\n", maskInfo.mask);
    printf(" \"cidr\":\"%d\",\n", maskInfo.cidr);
    printf(" \"networkaddress\":\"%s\",\n", networkAddress);
    printf(" \"broadcastaddress\":\"%s\",\n", broadcastAddress);
    printf(" \"range\":\"%s\",\n", range);

    if (countOfIPs == currentIP)
        printf(" \"hosts\":\"%d\"\n}\n]\n", maskInfo.hosts);
    else
        printf(" \"hosts\":\"%d\"\n},", maskInfo.hosts);
}

void printCIDR()
{
    printf("\n  %-9s %-15s %20s \n", "Prefix","Subnet Mask" ,"Number of Hosts");

    for (int i = 0; i < PREFIXES; i++)
    {
        char *color = NULL;

        if (subnetMasks[i].class == CLASS_A && i % 2)
            color = BOLD_RED;
        else if (subnetMasks[i].class == CLASS_A)
            color = ANSI_COLOR_RED;

        if (subnetMasks[i].class == CLASS_B && i % 2)
            color = ANSI_COLOR_BLUE;
        else if (subnetMasks[i].class == CLASS_B)
            color = BOLD_BLUE;

        if (subnetMasks[i].class == CLASS_C && i % 2)
            color = ANSI_COLOR_GREEN;
        else if (subnetMasks[i].class == CLASS_C)
            color = BOLD_GREEN;

        printf("|%s /%-8d %-15s %20d %s|\n",color,subnetMasks[i].cidr,subnetMasks[i].mask,subnetMasks[i].hosts,RESET_COLOR);
    }

    printf(RESET_COLOR "\n");

    exit(0);
}

// Dynamically create all the subnet masks from 255.0.0.0 - 255.255.255.252
// I might add in 255.255.255.254 the special /31
void createMaskArray(subnetMasksInfo masks[])
{
    for(int j = 0; j < MASK_MAX_BITS - OCTET_SIZE; j++)
    {
        // Start with 8 bits i.e 255.0.0.0
        char bits[MASK_MAX_BITS+1] = "11111111";
        int countOfOnes = OCTET_SIZE;

        for (int k = 0; k < j; k++)
        {
            bits[countOfOnes] = '1';
            countOfOnes ++;
        }

        int countOfZeros = 0;

        for (int l = countOfOnes; l < MASK_MAX_BITS; l++)
        {
            bits[l] = '0';
            countOfZeros++;
        }

        int arrayLocation = countOfOnes-OCTET_SIZE;

        // Copy the Bits array to the masks binary array
        strcpy(masks[arrayLocation].binary, bits);

        // Assign the cidr
        masks[arrayLocation].cidr = countOfOnes;

        // Assign the Class
        if (countOfOnes >= CLASS_A && countOfOnes < CLASS_B && countOfOnes < CLASS_C)
            masks[arrayLocation].class = CLASS_A;
        else if (countOfOnes >= CLASS_B && countOfOnes < CLASS_C)
            masks[arrayLocation].class = CLASS_B;
        else if (countOfOnes >= CLASS_C)
            masks[arrayLocation].class = CLASS_C;

        // Calc the amount of hosts
        masks[arrayLocation].hosts = pow(2,countOfZeros) - 2;
        char digitMask[SUBNETMASK_SIZE+SUBNETMASK_DOTS+1];
        convertBinarytoIP(digitMask, bits);

        strcpy(masks[arrayLocation].mask, digitMask);
    }
}

subnetMasksInfo findMaskInfo(int cidr)
{
    for (int i = 0; i < PREFIXES; i++)
    {
        if (cidr == subnetMasks[i].cidr)
            return subnetMasks[i];
    }

    subnetMasksInfo noneFound;
    noneFound.cidr = 0;

    return noneFound;
}

char* findCIDR(char *subnetMask)
{
    for (int i = 0; i < PREFIXES; i++)
    {
        if (strcmp(subnetMask, subnetMasks[i].mask) == 0)
            return convertIntToChar(subnetMasks[i].cidr);
    }

    return "0";
}

//And the binaries of the host address and the the subnet mask
//11000000 10101000 00000000 00000001  192.168.0.1      Host Address
//11111111 11111111 11111111 00000000  255.255.255.0    Subent Mask
//11000000 10101000 00000000 00000000  192.168.0.0      Network Address
void findNetworkAddress(char networkAddress[], char *ip, char *mask)
{
    char *binaryIP = malloc(sizeof *binaryIP *(MASK_MAX_BITS+1));
    convertIPtoBinary(binaryIP, ip);

    char *networkAddressBinary = malloc(sizeof *networkAddressBinary *(MASK_MAX_BITS+1));

    for(int i = 0; i < MASK_MAX_BITS; i++)
    {
        if (mask[i] == '1' && binaryIP[i] == '1')
            networkAddressBinary[i] = '1';
        else
            networkAddressBinary[i] = '0';
    }

    convertBinarytoIP(networkAddress, networkAddressBinary);
}

//Take the Host address and change the host bits to 1 the last bits x amount of bits x being cidr - 32
//1000000 10101000 00000000 00000001  192.168.0.1/24    Host Address
//24 - 32 = 8 so take the last 8 bits and change them to 1
//1000000 10101000 00000000 11111111  192.168.0.255     Broadcast Address
void findBroadcastAddress(char broadcastAddress[], char *hostAddress, int cidr)
{
    char *binaryIP = malloc(sizeof *binaryIP *(MASK_MAX_BITS+1));

    convertIPtoBinary(binaryIP, hostAddress);

    for (int i = cidr; i < MASK_MAX_BITS; i++)
    {
        binaryIP[i] = '1';
    }

    convertBinarytoIP(broadcastAddress, binaryIP);
}

void getIPRange(char *range, char *broadcastAddress, char *networkAddress)
{
    int firstHost = getLastOctet(networkAddress) + 1;
    int lastHost = getLastOctet(broadcastAddress) - 1;

    char firstHostChar[OCTET_DIGIT_SIZE+1];
    char lastHostChar[OCTET_DIGIT_SIZE+1];

    sprintf(firstHostChar, "%d", firstHost);
    sprintf(lastHostChar, "%d", lastHost);

    char *lowRange = stripLastOctetOff(networkAddress);
    lowRange[strcspn(lowRange, "\n")] = '\0';

    char *highRange = stripLastOctetOff(broadcastAddress);
    highRange[strcspn(highRange, "\n")] = '\0';

    strcpy(range, lowRange);
    strcat(range, firstHostChar);
    strcat(range, " - ");
    strcat(range, highRange);
    strcat(range, lastHostChar);

}

char* stripLastOctetOff(char address[])
{
    int octetCount = 0;
    int lastOctetCount = 0;
    char *octets = malloc(sizeof *octets *(SUBNETMASK_SIZE + SUBNETMASK_DOTS+1));

    for (int i = 0; i <= SUBNETMASK_SIZE + SUBNETMASK_DOTS; i++)
    {
        if (address[i] == '.' || address[i] == '\0')
        {
            lastOctetCount++;

            if (lastOctetCount == 3)
            {
                octets[octetCount] = '.';
                break;
            }
        }

        octets[octetCount] = address[i];

        octetCount++;
    }
    octets[octetCount+1] = '\n';

    return octets;
}

int getLastOctet(char ip[])
{
    int octetCount = 0;
    int lastOctetCount = 0;
    char octets[SUBNETMASK_DOTS+1];

    for (int i = 0; i <= SUBNETMASK_SIZE + SUBNETMASK_DOTS; i++)
    {
        if (ip[i] == '.' || ip[i] == '\0')
        {
            octetCount = 0;
            octets[OCTET_DIGIT_SIZE] = '\0';

            lastOctetCount++;

            if (lastOctetCount == 4)
                return atoi(octets);

            // Clear out the array
            memset(octets, 0, sizeof octets);
        }
        else
        {
            octets[octetCount] = ip[i];
            octetCount++;
        }
    }

    return 0;
}

void convertBinarytoIP(char ip[], char *bits)
{
    for (int i = 0; i < OCTETS; i ++)
    {
        char octChar[OCTETS+1];
        int oct = binaryToDec(bits,OCTET_SIZE, OCTET_SIZE*i);
        if (i == SUBNETMASK_DOTS)
            sprintf(octChar, "%d", oct);
        else
            sprintf(octChar, "%d.", oct);

        if (i == 0)
            strcpy(ip,octChar);
        else
            strcat(ip,octChar);
    }
}

void convertIPtoBinary(char binaryIP[], char *ip)
{
    int octetCount = 0;
    int lastOctetCount = 0;
    char octets[SUBNETMASK_DOTS+1];

    for (int i = 0; i <= SUBNETMASK_SIZE + SUBNETMASK_DOTS; i++)
    {
        if (ip[i] == '.' || ip[i] == '\0')
        {
            octetCount = 0;
            octets[OCTET_DIGIT_SIZE] = '\0';
            strcat(binaryIP, decToBinary(atoi(octets),8));

            // Clear out the array
            memset(octets, 0, sizeof octets);

            lastOctetCount++;
            if (lastOctetCount == 4)
                break;
        }
        else
        {
            octets[octetCount] = ip[i];
            octetCount++;
        }
    }
    binaryIP[MASK_MAX_BITS] = '\0';
}

char* convertIntToChar(int num)
{
    char *buf = malloc(sizeof(char*) * 3);;
    snprintf(buf, sizeof buf, "%d", num);

    return buf;
}

char* decToBinary(int dec, int bits)
{
    char *binaryNumber = malloc(sizeof(char*) * 3);

    for(int i = bits - 1; i >= 0; i--){
        if((dec & (1 << i)) != 0)
            strcat(binaryNumber, "1");
        else
            strcat(binaryNumber, "0");
    }

    return  binaryNumber;
}

int binaryToDec(char *binary, int arrayCount, int bitsToSkip)
{
    int p = 0;
    int dec = 0;

    for (int j = arrayCount - 1 + bitsToSkip; j >= 0 + bitsToSkip; j-- ) 
    {
        dec +=  (binary[j] - 48) * (int)pow((double)2, p);
        p++;
    }

    return dec;
}

bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

char *trimWhiteSpace(char *str)
{
  char *end;

  while(isspace((unsigned char)*str)) str++;

  if(*str == 0)
    return str;

  end = str + strlen(str) - 1;
  while(end > str && isspace((unsigned char)*end)) end--;

  *(end+1) = 0;

  return str;
}

void printHelp()
{
    printf("IP Calculator will calculate all relevant information for an IP. You can input a single IP or pipe IPs in from anything\n");
    printf("Variables:\n");
    printf("-c Display subnetmask and CIDR table\n");
    printf("-x Display the results in XML format\n");
    printf("-j Display the results in JSON format\n");
    printf("-h Display the help\n");
    printf("Examples:\n");
    printf("./ip-calculator 192.168.0.10/24\n");
    printf("./ip-calculator 192.168.0.10 255.255.255.0\n");
    printf("cat ips.txt | ./ip-calculator\n");
    printf("cat ips.txt | ./ip-calculator -j\n");

    exit(0);
}
