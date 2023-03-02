#pragma once

#include<obliv.h>

void auction(void *args);

typedef struct protocolIO{
  int buyer1Share;
  int buyer2Share;
  int buyer3Share;
  int seller1Share;
  int seller2Share;
  int seller3Share;
  int R1;
  int R2;
  int R3;
  int C1;
  int C2;
  int C3;
} protocolIO;
