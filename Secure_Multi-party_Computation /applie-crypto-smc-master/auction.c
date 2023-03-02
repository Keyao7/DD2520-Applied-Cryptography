#include<stdio.h>
#include<obliv.h>

#include"auction.h"

int main(int argc, char** argv){

  if(argc != 4){
    fprintf(stderr, "Usage: %s <port> <--|localhost> <inputFIle>\n", argv[0]);
    return 2;
  }

  ProtocolDesc pd;
  protocolIO io;

  // Read inputs from file
  FILE* file;
  file = fopen(argv[3], "r");

  char* errorMsg = "Input file must me in format:\nOPERAND_1\nOPERAND_2\nOPERAND_3\n";
  if(fscanf(file, "%d\n", &io.buyer1Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  } if (fscanf(file, "%d\n", &io.buyer2Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  } if (fscanf(file, "%d\n", &io.buyer3Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  } if (fscanf(file, "%d\n", &io.seller1Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  } if (fscanf(file, "%d\n", &io.seller2Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  } if (fscanf(file, "%d\n", &io.seller3Share) == EOF){
    fprintf(stderr, errorMsg);
    return 2;
  }


  fclose(file);

  const char* remote_host = (strcmp(argv[2], "--")==0?NULL:argv[2]);
 // ocTestUtilTcpOrDie(&pd, remote_host, argv[1]);
  if(!remote_host){
    if(protocolAcceptTcp2P(&pd, argv[1])){
      fprintf(stderr, "TCP accept failed\n");
      exit(1);
    }
  }
  else{
    if(protocolConnectTcp2P(&pd,remote_host,argv[1])!=0){
      fprintf(stderr,"TCP connect failed\n");
      exit(1);
    }
  }

  int currentParty = remote_host?2:1;
  setCurrentParty(&pd, currentParty); 

  execYaoProtocol(&pd, auction, &io);

  fprintf(stderr, "R1: result = %d\n", io.R1);
  fprintf(stderr, "R2: result = %d\n", io.R2);
  fprintf(stderr, "R3: result = %d\n", io.R3);

  fprintf(stderr, "C1: result = %d\n", io.C1);
  fprintf(stderr, "C2: result = %d\n", io.C2);
  fprintf(stderr, "C3: result = %d\n", io.C3);




  cleanupProtocol(&pd);
  return 0;
}
