/// \file firewall.c
/// \brief Reads IP packets from a named pipe, examines each packet,
/// and writes allowed packets to an output named pipe.
/// Author: Chris Dickens (RIT CS)
///
///
/// This file contains proprietary information. Distribution is limited
/// to Rochester Institute of Technology faculty, students currently enrolled
/// in CSCI243: The Mechanics of Programming, graders, and student lab
/// instructors. Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department. The
/// content of this file is protected as an unpublished work.
///
/// Copyright 2015 Rochester Institute of Technology
///
///

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "filter.h"

#define MAX_PACKET_LENGTH 2500

/// Type used to control the mode of the firewall
typedef enum FilterMode_e
{
   MODE_BLOCK_ALL = 1,
   MODE_ALLOW_ALL = 2,
   MODE_FILTER = 3
} FilterMode;


/// The input named pipe, "ToFirewall"
static FILE* InPipe = NULL;


/// The output named pipe, "FromFirewall"
static FILE* OutPipe = NULL;


/// Controls the mode of the firewall
volatile FilterMode Mode = MODE_FILTER;


/// The main function that performs the actual packet read, filter, and write.
/// The return value and parameter must match those expected by pthread_create.
/// @param args A pointer to a filter
/// @return Always NULL
static void* FilterThread(void* args);


/// Displays the menu of commands that the user can choose from.
static void DisplayMenu(void);


/// Opens the input and output named files.
/// @return True if successful
static bool OpenPipes(void);


/// Reads a packet from the input name pipe.
/// @param buf Destination buffer to write the packet into
/// @param bufLength The length of the supplied destination buffer
/// @param len The length of the packet
/// @return True if successful
static bool ReadPacket(unsigned char* buf, int* charsRead, int* len);


/// The main function. Creates a filter, configures it, launches the
/// filtering thread, handles user input, and cleans up resources when
/// exiting.  The intention is to run this program with a command line
/// argument specifying the configuration file to use.
/// @param argc Number of command line arguments
/// @param argv Command line arguments
/// @return EXIT_SUCCESS or EXIT_FAILURE
int main(int argc, char* argv[])
{
   // TODO: implement function

   char input[20];
   short mode;
   pthread_t filterThread;
   int rc;

   if (argc != 2){
       fprintf(stderr, "usage: firewall <config_file>\n");
       return EXIT_SUCCESS;
   }
   IpPktFilter filter = CreateFilter();
   if (!ConfigureFilter(filter, argv[1])){
       return EXIT_FAILURE;
   }

   rc = pthread_create(&filterThread, NULL, FilterThread, (void*) filter);

   if (rc){
      fprintf(stderr, "Could not create filter thread");
      return EXIT_FAILURE;
   }

   DisplayMenu();
   while(Mode){
      printf("> ");
      char* s = fgets(input, 20 , stdin);
      if (s){};
      mode = ((short) input[0]) -48;

      if (mode == MODE_BLOCK_ALL){
         Mode = MODE_BLOCK_ALL;
      }
      else if (mode == MODE_ALLOW_ALL){
         Mode = MODE_ALLOW_ALL;
      }
      else if (mode == MODE_FILTER){
         Mode = MODE_FILTER;
      }
      else if (mode == 0){
         Mode = 0;
         pthread_join(filterThread, NULL);
         break;
      }

   }

   DestroyFilter(filter);
   return EXIT_SUCCESS;
}


/// Runs as a thread and handles each packet. It is responsible
/// for reading each packet in its entirety from the input pipe,
/// filtering it, and then writing it to the output pipe. The
/// single void* parameter matches what is expected by pthread.
/// @param args An IpPktFilter
/// @return Always NULL
static void* FilterThread(void* args)
{
   // TODO: implement function
   IpPktFilter filter = (IpPktFilter) args;
   unsigned char buffer[MAX_PACKET_LENGTH];
   int pktLength;
   int charsRead;
   bool isFinished = true;
   bool isSuccess;

   OpenPipes();

   while(Mode){

      if (feof(InPipe)==0){
         if (isFinished ){
            isSuccess = fread(&pktLength, sizeof(int), 1, InPipe);
            if (isSuccess){};
         }
         isFinished = ReadPacket(buffer, &charsRead, &pktLength);
         bool isBlocked = false;

         if (Mode == MODE_BLOCK_ALL){
            isBlocked = true;
         }
         else if (Mode == MODE_ALLOW_ALL){
            isBlocked = false;
         }
         else if (Mode == MODE_FILTER){
            isBlocked = ! FilterPacket(filter, buffer);
         }
         else if (Mode == 0){
            break;
         }

         if (!isBlocked){
            fwrite(&pktLength, sizeof(int), 1, OutPipe);
            fwrite(buffer, sizeof(unsigned char), pktLength, OutPipe);
            fflush(OutPipe);
         }
         pktLength -= charsRead;
      }
   }

   fclose(InPipe);
   fclose(OutPipe);

   return NULL;
}



/// Print a menu and a prompt to stdout
static void DisplayMenu(void)
{
   printf("\n1. Block All\n");
   printf("2. Allow All\n");
   printf("3. Filter\n");
   printf("0. Exit\n");
}


/// Open the input and output named pipes that are used for reading
/// and writing packets.
/// @return True if successful
static bool OpenPipes(void)
{

   InPipe = fopen("ToFirewall", "rb");
   if(InPipe == NULL)
   {
      perror("ERROR, failed to open pipe ToFirewall:");
      return false;
   }

   OutPipe = fopen("FromFirewall", "wb");
   if(OutPipe == NULL)
   {
      perror("ERROR, failed to open pipe FromFirewall:");
      return false;
   }

   return true;
}


/// Read an entire IP packet from the input pipe
/// @param buf Destination buffer for storing the packet
/// @param charsRead The number of chars read into the buffer
/// @param len The length of the packet
/// @return True if a packet was successfully read
static bool ReadPacket(unsigned char* buf, int* charsRead, int* len)
{
   // TODO: implement function
   unsigned int bytes_to_read = fread(buf,sizeof(char),*len,InPipe);
   bool isFinished = false;
   if (bytes_to_read==sizeof(char)*(*len))
      isFinished = true;
    else
      isFinished = false;
  *charsRead = bytes_to_read/sizeof(char);
  return isFinished;
}
