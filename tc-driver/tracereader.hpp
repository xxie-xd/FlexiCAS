#ifndef CM_TC_DRIVER_TRACEREADER_HPP
#define CM_TC_DRIVER_TRACEREADER_HPP
#include <string>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstdint>
#include <functional>

class TraceReader {
  std::string pname;
  std::ifstream fTrace;
  char * traceBuf;
  const int traceMaxSize = 256;

  void setExecutor(std::function<void(uint64_t, uint64_t, uint64_t, bool, uint64_t)> executor_) {
    executorSet = true;
    executor = executor_;
  }
  TraceReader(std::string pname_)
    : pname(pname_)
  {
    traceFileCnt.resize(3);
    traceCnt.resize(3);
    curTraceCnt = 0;
    curTraceType = Init;
    traceFileCnt[curTraceType] = 0;
    curTraceFname = std::string(tracePrefix[curTraceType] + "-" +
          pname + "-" +
          std::to_string(traceFileCnt[curTraceType]) + ".dat");
    fTrace.open(curTraceFname);
    traceBuf = new char [traceMaxSize];
  }

public:
  TraceReader(std::string pname_, std::function<void(uint64_t, uint64_t, uint64_t, bool, uint64_t)> executor_)
    : TraceReader(pname_){
      setExecutor(executor_);
      eventDispatch(InitStart);
    }

  ~TraceReader() 
  {
    delete [] traceBuf;
    traceBuf = nullptr;
  }

  enum TraceType {Init, Warm, Trace};
  const std::string tracePrefix [3] = {"init", "warm", "trace"};

  std::vector<uint64_t> traceFileCnt;
  std::vector<uint64_t> traceCnt;

  TraceType curTraceType;
  uint64_t curTraceCnt;

  std::string curTraceFname;

  typedef std::function<void(uint64_t, uint64_t, uint64_t, bool, uint64_t)> executor_t;

  enum Event { InitStart, InitEnd, WarmStart, WarmEnd, TraceStart, TraceEnd, SwitchFile, NumOfEvent};
  typedef std::function<void(Event)> event_handler_t;
  void setEventHandler(event_handler_t handler_) {
    eventHandler.push_back(handler_);
  }
protected:
  bool executorSet = false;
  executor_t executor;

  std::vector<event_handler_t> eventHandler;

  void eventDispatch(Event event) {
    if (event >= NumOfEvent) return;
    for (auto handler : eventHandler) {
      handler(event);
    }
  }

  bool getNextTrace(void) {
    std::string nextTraceSameType(tracePrefix[curTraceType] + "-" +
    pname + "-" + 
    std::to_string(traceFileCnt[curTraceType]+1) + ".dat");

    fTrace.open(nextTraceSameType);
    if (fTrace.is_open()) {
      traceFileCnt[curTraceType] ++;
      eventDispatch(SwitchFile);
      return true;
    }
    else {
      // Traces in this type are all consumed.
      // Turn to next Type.
      traceCnt[curTraceType] = curTraceCnt;
      traceFileCnt[curTraceType] ++;

      if (curTraceType == Init || curTraceType == Warm) {
        curTraceCnt = 0;
        if (curTraceType == Init) {
          eventDispatch(InitEnd);
          curTraceType = Warm;
        }
        else {
          eventDispatch(WarmEnd);
          curTraceType = Trace;
        }

        curTraceFname = std::string(tracePrefix[curTraceType] + "-" +
          pname + "-" +
          std::to_string(traceFileCnt[curTraceType]) + ".dat");
        
        fTrace.open(curTraceFname);
        eventDispatch(SwitchFile);
        if (curTraceType == Warm) {
          eventDispatch(WarmStart);
        } else if (curTraceType == Trace) {
          eventDispatch(TraceStart);
        }
        return true;
      }
      else if (curTraceType == Trace) {
        // All trace is read.
        eventDispatch(TraceEnd);
        return false;
      }
      else {
        // shouldn't be here.
        return false;
      }
    }
  }

  void execute(uint64_t t_start, uint64_t t_delta, uint64_t pa, bool rw, uint64_t tagvalue) {
    if (executorSet) {
      executor(t_start, t_delta, pa, rw, tagvalue);
    }
    else if (!executorSet) {
      throw std::runtime_error("Executor is not set.");
    }
  }

  void decodeAndExecute(void);

  void readCurTraceFile() {
    if (!fTrace.is_open()) {
      std::cerr << "Trace " << curTraceFname << " read failed.\n"; 
      return;
    }

    while (fTrace.getline(traceBuf, traceMaxSize))
      decodeAndExecute();

    fTrace.close();
  }

public:
  void run(void) {
    do {
      readCurTraceFile();
    }while(getNextTrace());
  }

  bool runPeroid(uint64_t peroid) {
    for (uint64_t i = 0; i < peroid; i++) {
      if (!fTrace.is_open()) {
        std::cerr << "Trace " << curTraceFname << " read failed.\n"; 
        return false;
      }

      if (fTrace.getline(traceBuf, traceMaxSize))
        decodeAndExecute();
      else if (fTrace.eof()) {
        fTrace.close();
        if (!getNextTrace()) {
          return false;
        }
        return true;
      }
      else {
        std::cerr << "Trace " << curTraceFname << " read error.\n";
        return false;
      }
      
    }

    return true;
  }

  void traceDisplay(uint64_t t_start, uint64_t t_delta, uint64_t pa, bool rw, uint64_t tagvalue) {
    std::cout << std::hex
      << t_start
      << "|" << t_delta
      << ": pa " << pa 
      << " ";
    
    if (!rw) std::cout << "Read" ;
    else std::cout << "Write 0x" <<  tagvalue;
            
    std::cout << std::noshowbase << std::endl;
  }

  void traceFileStat(void) {
    std::cout << std::dec 
      << "TraceType\tFileCnt" << std::endl 
      << "Init" << "\t" << traceFileCnt[Init] << std::endl 
      << "Warm" << "\t" << traceFileCnt[Warm] << std::endl
      << "Data" << "\t" << traceFileCnt[Trace] 
      << std::noshowbase << std::endl;
  }
};


#endif // CM_TC_DRIVER_TRACEREADER_HPP