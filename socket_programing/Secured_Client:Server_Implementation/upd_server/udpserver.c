#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <openssl/sha.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "packet.h"
#include "helper_functions.c"

int main(int argc, char *argv[])
{
  // Data to send to client
  char *datamsg = (char *)malloc(sizeof datamsg);

  // The packet counter
  unsigned int packetcou = 1;

  // The result of the hash function
  unsigned char sha1_hash[20];
  char sha1_hash_str[20];
  SHA_CTX c;
  int result;

  // Socket descriptor and additional variables for handling the connection
  int sockfd;
  struct addrinfo hints, *servinfo, *p;
  int rv, numbytes;
  char *server_port;
  char *passwd;

  // Instance of the union packet and while-flag
  Packets packet;
  int quitFlag = 1;

  // Needed for the sendto() and recvfrom()
  struct sockaddr_storage their_addr;
  socklen_t addr_len = sizeof their_addr;

  // File to send
  char *fileIn;

  /*
    SETUP THE SOCKET CONNECTION,
    AND BE SURE THAT A CONNECTION IS ACTUALLY BEEN MADE.
    */
  if (argc != 4)
  {
    printf("Not enough or too many arguments\n");
    exit(1);
  }
  server_port = argv[1];
  passwd = argv[2];
  fileIn = argv[3];

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, server_port, &hints, &servinfo)) != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("listener: socket");
      continue;
    }
    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sockfd);
      perror("listener: bind");
      continue;
    }
    break;
  }
  if (p == NULL)
  {
    fprintf(stderr, "listener: failed to bind socket\n");
    return 2;
  }
  printf("Waiting for download...\n");
  addr_len = sizeof their_addr;

  // Implement protocol specification
  while (quitFlag)
  {
    // Receiving a packet from client and processing it
    if ((numbytes = recvfrom(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, &addr_len)) == -1)
    {
      perror("listener: recvfrom");
      exit(1);
    }
    // Check the header
    switch (ntohs(packet.ctrl_msg.header))
    {
    case JOIN_REQ:                       // Receive JOIN_REQ packet from client. Send PASS_REQ to client
      packet.ctrl_msg.header = htons(2); //PASS_REQ header is 2
      if ((numbytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
      {
        perror("listener: JOIN_REQ");
        exit(1);
      }
      break;

    case PASS_RESP: // Receive PASS_RESP_PACKET to client.
      if (packetcou <= 3)
      {
        if (strcmp(packet.pass_resp.password, passwd) == 0) //passwd is correct
        {
          // Send a ACCEPT packet
          packet.ctrl_msg.header = htons(4); //PASS_ACCEPT header is 4
          if ((numbytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
          {
            perror("listener: ACCEPT");
            exit(1);
          }

          // Read data from txt file (test.txt) and Send it
          datamsg = (char *)read_inputtext(fileIn);
          strcpy(packet.data.data, datamsg);
          packet.ctrl_msg.header = htons(5); //DATA header is 5
          if ((numbytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
          {
            perror("listener: DATA");
            exit(1);
          }

          // Calculate SHA1-Digest of the data
          result = SHA1_Init(&c);
          if (result == 1)
          {
            printf("SHA1_Init success!\n");
          }
          else
          {
            printf("SHA1_Init error!\n");
            return -1;
          }

          result = SHA1_Update(&c, datamsg, strlen(datamsg));
          if (result == 1)
          {
            printf("SHA1_Update success!\n");
          }
          else
          {
            printf("SHA1_Update error!\n");
            return -2;
          }

          result = SHA1_Final(sha1_hash, &c);
          if (result == 1)
          {
            printf("SHA1_Final success!\n");
          }
          else
          {
            printf("SHA1_Final error!\n");
            return -3;
          }

          //Convert 20 byte Hex values sha1_hash to string sha1_hash_str
          for (int i = 0; i < sizeof(sha1_hash); i++)
          {
            sprintf(sha1_hash_str + (i * 2), "%02x", sha1_hash[i]);
          }
          printf("SHA1-Digest: %s\n", sha1_hash_str);
          strcpy(packet.terminate.digest, (char *)sha1_hash);

          // Send TERMINATE packet
          packet.ctrl_msg.header = htons(6); //TERMINATE header is 6
          if ((numbytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
          {
            perror("listener: TERMINATE");
            exit(1);
          }

          printf("Download Completed Sucessfully!\n");
          quitFlag = 0;
        }
        else //passwd is not correct. Send another PASS_REQ
        {
          packetcou++;
          packet.ctrl_msg.header = htons(2);
          if ((numbytes = sendto(sockfd, &(packet.ctrl_msg), sizeof(packet.ctrl_msg), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
          {
            perror("listener: another PASS_REQ");
            exit(1);
          }
        }
      }
      else // Send a REJECT to client after 3 wrong passwords
      {
        packet.ctrl_msg.header = htons(7); //REJECT header is 7
        if ((numbytes = sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&their_addr, addr_len)) == -1)
        {
          perror("listener: REJECT");
          exit(1);
        }
        printf("ABORT!\n");
        quitFlag = 0;
      }
      break;

    default:
      quitFlag = 0;
      break;
    }
  }
  return 0;
}
