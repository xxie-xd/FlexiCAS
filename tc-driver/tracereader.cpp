#include "tc-driver/tracereader.hpp"
#include <cstring>


void TraceReader::decodeAndExecute()
{
  uint64_t t_start;
  uint64_t t_delta;
  uint64_t pa ;
  uint64_t tagvalue;
  bool rw ;

  if (traceBuf[0] == 0)
    return ;
  if (curTraceType == Init) {
    char * token;
    token = strtok(traceBuf, ",");
    pa = std::strtoull(token, NULL, 16);
    token = strtok(NULL, ",");
    tagvalue = std::strtoull(token, NULL, 16);
#ifdef DEBUG
    traceDisplay(0,0,pa,true,tagvalue);
#endif
    execute(0,0,pa,true,tagvalue);
    curTraceCnt ++;
  }
  else if (curTraceType == Warm) {
    char * token;
    token = strtok(traceBuf, ",");
    token = strtok(NULL,",");
    token = strtok(NULL,",");
    pa = std::strtoull(token,NULL,16);
    token = strtok(NULL,",");
    rw = std::stoi(token);
    if (rw) {
      token = strtok(NULL, ",");
      tagvalue = std::strtoull(token,NULL,16);
    }
#ifdef DEBUG
    traceDisplay(0,0,pa,rw,tagvalue);
#endif 
    execute(0,0,pa,rw,tagvalue);
    curTraceCnt ++;
  }
  else if (curTraceType == Trace) {
    char * token;
    token = strtok(traceBuf, ",");
    t_start = std::strtoull(token, NULL, 16);
    token = strtok(NULL, ",");
    t_delta = std::strtoull(token, NULL, 16);
    token = strtok(NULL, ",");
    pa = std::strtoull(token ,NULL, 16);
    token = strtok(NULL, ",");
    rw = std::stoi(token);
    if (rw) {
      token = strtok(NULL, ",");
      tagvalue = std::strtoull(token, NULL, 16);
    }
#ifdef DEBUG
    traceDisplay(t_start, t_delta, pa, rw, tagvalue);
#endif
    execute(t_start,t_delta,pa,rw,tagvalue);
    curTraceCnt++;
  }
}