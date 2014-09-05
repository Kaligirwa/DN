#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* to parse Ethernet headers. */
#include <netinet/ip.h> /* to parse IP headers. */
#include <netinet/tcp.h> /* to parse TCP headers. */
#include <string>
#include "Frame.h"

#define  NUM_FILES 5
void read_files (char*file_names[], int num_files);
void print_headers (struct ether_header ether, struct ip hdr);

/* How to run:
 * compile from terminal: "g++ project_1.cpp frame.cpp"
 * run ./a.out <files paths - at least one file> for example: ./a.out http.ok.bin syn.bin
 *
 *
 * Specifics: 
 * This program takes as input a list of files to read frames from 
 * It reads the file starting with the first one
 * Initializes one object Frame which will be used for all the frames read 
 * 
 * Improvements: 
 * create an array of objects for data persistence
 */



int main(int argc,char** argv){
    
    
    int num_files = argc-1;
    char * file_names [num_files];   //array of file names
    if (argc < 1) {
        printf ("enter file names");
        exit(1);
    }
    
    for (int i = 0; i < argc; i++) {
        //read all the file names from argv
        file_names[i] = argv[i+1];
    }
    
        read_files(file_names,num_files);

}


void read_files(char* file_names[], int num_files) {
    
    //for every file read the contents
    FILE *inFile;
    int position;
    
    FILE *outFile;
    outFile = fopen ("output.txt", "w");
    if (outFile == NULL){
        printf ("Output File Error!\n");
        exit (1);
    }
    rewind(outFile);
    for (int i = 0; i < num_files; i++)
    {
        //open the current file
        printf ("FILE[%d]: %s\n", i+1, file_names[i]);
        printf ("***************************\n\n");
        fprintf (outFile, "FILE[%d]: %s\n", i+1, file_names[i]);
        fprintf (outFile, "***************************\n\n");
        inFile = fopen (file_names[i], "rb");
        
        //test for errors
        if (inFile == NULL) {
            printf ("File error: %s!\n", file_names[i]);
            exit (1);
        }
        
        //get the size of the whole file
        fseek (inFile, 0, SEEK_END);
        int fSize = ftell (inFile);
        rewind (inFile);
        
        //offset one because we set the offset to 7 octets
        //indeed for subsequent frames, we only notice the end of the frame after reading the first '55'
        //thus the need to offset only by 7 octets
        fseek (inFile, 1, SEEK_CUR);
        
        //initialize a Frame object
        Frame* frame = new Frame;
        
        //read the file
        //parse frame by frame
        while (inFile && ftell(inFile) < fSize) {
            frame->parse(inFile);
            frame->display(outFile);
            //position = frame->read_rest(inFile);
            
        }
     
        delete frame;
    }
    
}


