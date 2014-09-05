//
//  frame.h
//  
//
//  Created by Nathalie Kaligirwa on 9/3/14.
//
//

#ifndef ____frame__
#define ____frame__

#include <iostream>
//#include "frame.h"
#include <iostream>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* to parse Ethernet headers. */
#include <netinet/ip.h> /* to parse IP headers. */
#include <netinet/tcp.h> /* to parse TCP headers. */
#include <string>
#include <stdlib.h>

#define OFFSET 5
//using namespace std;

class Frame
{
    
    
private:
    
    struct ether_header *ether;              // the ethernet header
    struct ip *hdr;                          // the ip header
    void ether_parse(FILE * inFile);         // function to parse the ethernet header
    void ip_parse(FILE * inFile);            // function to parse the ip header
    void ether_display(struct ether_header ether,FILE *outFile);
    void ip_display (struct ip hdr,FILE *outFile);
    int  offset; 
    
public:
    //Constructor;
    Frame();
    //Destructor;
    ~Frame();
    void display(FILE *outFile);
    int  parse(FILE* inFile);
    int  read_rest (FILE* inFile);
   
    
};
#endif /* defined(____frame__) */
