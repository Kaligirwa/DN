//
//  frame.cpp
//  
//
//  Created by Nathalie Kaligirwa on 9/3/14.
//
//

#include "frame.h"

//constructor
Frame::Frame()
{
    
    ether = (struct ether_header*) malloc (sizeof(struct ether_header));
    hdr   = (struct ip*) malloc (sizeof(struct ip));
    
}

//destructor
Frame::~Frame()
{
    delete ether;
    delete hdr;
    
}

//private functions
//*****************
//parse the ethernet header
void Frame::ether_parse(FILE* inFile) {
    fseek (inFile,sizeof(char)*OFFSET,SEEK_CUR);
    int result = fread (ether,1,sizeof(struct ether_header), inFile);
    if (result != sizeof(ether_header)) {
        printf ("ether parse:  ---- error reading file \n");
        exit(1);
    }
}

//parse the ip header
void Frame::ip_parse(FILE* inFile)    {
    int result = fread (hdr,1, sizeof(struct ip),inFile);
    if (result != sizeof(ip)) {
        printf ("ip parse:  ---- error reading file\n");
        exit(1);
    }
}

//parse the version and padding
int Frame::read_rest (FILE* inFile)
{
    char c;
    int pos;
    c = fgetc (inFile);
    
    while (c !=EOF) {
        if ((unsigned int)c == 85) {
            pos = ftell(inFile);
            break;
        }
        c = fgetc (inFile);
    }
    
    return pos;
}

//display the ethernet header
void Frame::ether_display(struct ether_header ether,FILE *outFile)
{
    printf ("ETHER:\t-----Ether Header-----\n");
    printf ("ETHER:\tPacket Size\t:\t%lu bytes \n", sizeof(ether)+sizeof(hdr));
    printf ("ETHER:\tDestination\t:\t%02x-%02x-%02x-%02x-%02x-%02x\n", ether.ether_dhost[0],
            ether.ether_dhost[1],
            ether.ether_dhost[2],
            ether.ether_dhost[3],
            ether.ether_dhost[4],
            ether.ether_dhost[5]);
    printf ("ETHER:\tSource\t\t:\t%02x-%02x-%02x-%02x-%02x-%02x \n", ether.ether_shost[0],
            ether.ether_shost[1],
            ether.ether_shost[2],
            ether.ether_shost[3],
            ether.ether_shost[4],
            ether.ether_shost[5]);
    printf ("ETHER:\tEthertype\t:\t%04x\n", ether.ether_type);
    printf ("ETHER:\t");
    printf ("\t\n \n");
    

    fprintf (outFile, "ETHER:\t-----Ether Header-----\n");
    fprintf (outFile, "ETHER:\tPacket Size\t:\t%lu bytes \n", sizeof(ether)+sizeof(hdr));
    fprintf (outFile,"ETHER:\tDestination\t:\t%02x-%02x-%02x-%02x-%02x-%02x\n", ether.ether_dhost[0],
            ether.ether_dhost[1],
            ether.ether_dhost[2],
            ether.ether_dhost[3],
            ether.ether_dhost[4],
            ether.ether_dhost[5]);
    fprintf (outFile, "ETHER:\tSource\t\t:\t%02x-%02x-%02x-%02x-%02x-%02x \n", ether.ether_shost[0],
            ether.ether_shost[1],
            ether.ether_shost[2],
            ether.ether_shost[3],
            ether.ether_shost[4],
            ether.ether_shost[5]);
    fprintf (outFile, "ETHER:\tEthertype\t:\t%04x\n", ether.ether_type);
    fprintf (outFile, "ETHER:\t");
    fprintf (outFile, "\t\n \n");

    
}

void display_flags() {
 
    
}

//display the ip header
void Frame::ip_display(struct ip hdr,FILE *outFile)
{
    printf ("IP:\t-----IP Header-------\n");

    printf ("IP:\tVersion\t\t=\t%d \n", hdr.ip_v);
    printf ("IP:\tHeader length\t=\t%d bytes\n", hdr.ip_hl);
    printf ("IP:\tType of service\t=\t0x%02x\n", hdr.ip_tos);
    printf ("IP:\tTotal length\t=\t%d\n", hdr.ip_ttl);
    printf ("IP:\tIdentification\t=\t%d\n", hdr.ip_id);
    printf ("IP:\tFlags\t=\t0x%02x\n", (((hdr.ip_off |= 0x4000)&0xF000) >> (sizeof(hdr.ip_off)*8-4)));
    printf ("\t\t");
 
    for (int i = 0; i < sizeof(hdr.ip_off)/2*8; i++) {
       
        if (i !=1)             {printf (".");}
        else                   {printf ("%u", (hdr.ip_off>>((sizeof(hdr.ip_off)*8)-i)));}
        if (i%4 == 0 && i!=0)  {printf ("\t");}
    
    }
    printf ("\t=\tdo not fragment\n");
    printf ("\t\t");
    for (int i = 0; i < sizeof(hdr.ip_off)/2*8; i++) {
        
        if (i !=2)            {printf (".");}
        else                  {printf ("%u", (hdr.ip_off>>((sizeof(hdr.ip_off)*8)-i)));}
        if (i%4 == 0 && i!=0) {printf ("\t");}
        
    }
    printf ("\t=\tlast fragment\n");

    printf ("IP:\t%u\t\t=\tlast flag\n", (hdr.ip_off |= 0x2000)&0xF000);
    printf ("IP:\tProtocol\t=\t%04x\n", hdr.ip_p);
    printf ("IP:\tHeader checksum\t=\t%04x\n",hdr.ip_sum);
    printf ("IP:\tSource address\t=\t%s\n", inet_ntoa (hdr.ip_src));
    printf ("IP:\tDestination address=\t%s\n", inet_ntoa (hdr.ip_dst));
    printf ("\n \n");
    
    fprintf (outFile, "IP:\t-----IP Header-------\n");
    
    fprintf (outFile, "IP:\tVersion\t\t=\t%d \n", hdr.ip_v);
    fprintf (outFile, "IP:\tHeader length\t=\t%d bytes\n", hdr.ip_hl);
    fprintf (outFile, "IP:\tType of service\t=\t0x%02x\n", hdr.ip_tos);
    fprintf (outFile, "IP:\tTotal length\t=\t%d\n", hdr.ip_ttl);
    fprintf (outFile, "IP:\tIdentification\t=\t%d\n", hdr.ip_id);
    fprintf (outFile, "IP:\tFlags\t=\t0x%02x\n", (((hdr.ip_off |= 0x4000)&0xF000) >> (sizeof(hdr.ip_off)*8-4)));
    fprintf (outFile, "\t\t");
  
    for (int i = 0; i < sizeof(hdr.ip_off)/2*8; i++) {
        
        if (i !=1)             {fprintf (outFile, ".");}
        else                   {fprintf (outFile, "%u", (hdr.ip_off>>((sizeof(hdr.ip_off)*8)-i)));}
        if (i%4 == 0 && i!=0)  {fprintf (outFile, "\t");}
        
    }
    fprintf (outFile, "\t=\tdo not fragment\n");
    fprintf (outFile, "\t\t");
    for (int i = 0; i < sizeof(hdr.ip_off)/2*8; i++) {
        
        if (i !=2)            {fprintf (outFile, ".");}
        else                  {fprintf (outFile, "%u", (hdr.ip_off>>((sizeof(hdr.ip_off)*8)-i)));}
        if (i%4 == 0 && i!=0) {fprintf (outFile, "\t");}
        
    }
    fprintf (outFile, "\t=\tlast fragment\n");
    
    fprintf (outFile, "IP:\t%u\t\t=\tlast flag\n", (hdr.ip_off |= 0x2000)&0xF000);
    fprintf (outFile, "IP:\tProtocol\t=\t%04x\n", hdr.ip_p);
    fprintf (outFile, "IP:\tHeader checksum\t=\t%04x\n",hdr.ip_sum);
    fprintf (outFile, "IP:\tSource address\t=\t%s\n", inet_ntoa (hdr.ip_src));
    fprintf (outFile, "IP:\tDestination address=\t%s\n", inet_ntoa (hdr.ip_dst));
    fprintf (outFile, "\n \n");

}


//public functions
//****************
//parse headers
int Frame::parse(FILE* inFile) {
    
    ether_parse(inFile);
    ip_parse(inFile);
    return read_rest (inFile);
    
}

//display headers
void Frame::display(FILE *outFile)
{
    ether_display (*ether, outFile);
    ip_display (*hdr, outFile);
}



