#include "cache/memory.hpp"
#include "util/cache_type.hpp"
#include "cache/tagcache.hpp"
#include "tc-driver/tracereader.hpp"

int test_input(DfiTaggerDataCacheInterface* dc_interface);

const uint64_t memsize = (16lu << 30); /// 16GiB Memory Region
const uint64_t tagsize = 2;
const uint64_t cacheblocksize = 64;
const int levels = 3; // fixed.

const int TTAW = 64;
const int TTIW = 3; // ilog2(8)
const int TTNW = 16;
const int TTIOff = 6; // ilog2(64)

const bool EnMon = true;

typedef MetadataMIBroadcast<TTAW,TTIW,TTIOff> TT_metadata_t;
typedef Data64B TT_data_t;
typedef IndexNorm<TTIW,TTIOff> TT_indexer_t;
typedef ReplaceLRU<TTIW,TTNW,true> TT_replacer_t;
typedef void TT_delay_t;

typedef CacheNorm<TTIW,TTNW,TT_metadata_t,TT_data_t,TT_indexer_t, TT_replacer_t, TT_delay_t, EnMon> TT_cache_t ;

const int MTTAW = 64;
const int MTTIW = 3; // ilog2(8)
const int MTTNW = 16;
const int MTTIOff = 6; // ilog2(64)

typedef MetadataMIBroadcast<MTTAW, MTTIW, MTTIOff> MTT_metadata_t;
typedef Data64B MTT_data_t;
typedef IndexNorm<MTTIW,MTTIOff> MTT_indexer_t;
typedef ReplaceLRU<MTTIW,MTTNW,true> MTT_replacer_t;
typedef void MTT_delay_t;

typedef CacheNorm<MTTIW,MTTNW,MTT_metadata_t,MTT_data_t,MTT_indexer_t, MTT_replacer_t, MTT_delay_t, EnMon> MTT_cache_t ;

const int MTDAW = 64;
const int MTDIW = 0; // ilog2(1)
const int MTDNW = 8;
const int MTDIOff = 6; // ilog2(64)

typedef MetadataMIBroadcast<MTDAW,MTDIW,MTDIOff> MTD_metadata_t;
typedef Data64B MTD_data_t;
typedef IndexNorm<MTDIW,MTDIOff> MTD_indexer_t;
typedef ReplaceLRU<MTDIW,MTDNW,true> MTD_replacer_t;
typedef void MTD_delay_t;

typedef CacheNorm<MTDIW,MTDNW,MTD_metadata_t,MTD_data_t,MTD_indexer_t, MTD_replacer_t, MTD_delay_t, EnMon> MTD_cache_t ;

typedef Data64B TagMemory_data_t;
typedef void TagMemory_delay_t;

typedef TagMemoryModel<TagMemory_data_t, TagMemory_delay_t, EnMon> TagMemory_t;


struct Executor_t {
  DfiTaggerDataCacheInterface* dc_interface;

  Executor_t(DfiTaggerDataCacheInterface* dc_interface) : dc_interface(dc_interface) {}
  void operator()(uint64_t t_start, uint64_t t_delta, uint64_t pa, bool rw, uint64_t tagvalue) {
    if(rw) {
      dc_interface->write_tag(pa, tagvalue, nullptr, tagsize);
    }
    else {
      dc_interface->read_tag(pa, nullptr, tagsize);
    }
  }

};

int test_trace(std::string stemname,Executor_t& executor) {
  TraceReader tr(stemname,executor);
  tr.run();
  tr.traceFileStat();
  return 0;
}

struct TagCacheDriver {
  TagConfig tag;
  CacheBase* tt,*mtt,*mtd;
  std::shared_ptr<TagCohPolicy> policy_tt, policy_mtt, policy_mtd;
  DfiTaggerDataCacheInterface* dc_interface;
  DfiTaggerOuterPortBase* outer;
  TagMemory_t *tag_mem;
  DfiTagger* dfi_tagger;
  std::array<MonitorBase*,3> acc_monitors;
  SimpleTracer *trace_monitor;
  Executor_t* executor;

  TagCacheDriver() {
    tag.record_mem(0, memsize , 64, tagsize);
    tag.record_tc(0,tagsize,cacheblocksize); /// Tag Table
    tag.record_tc(1,1,cacheblocksize); /// Meta Tag Table
    tag.record_tc(2,1,cacheblocksize); /// Meta Tag Directory

    tag.init();

    tt = new TT_cache_t("TT") ;
    mtt = new MTT_cache_t("MTT");
    mtd = new MTD_cache_t("MTD");

    policy_tt =   std::make_shared<TagCohPolicy>();
    policy_mtt =  std::make_shared<TagCohPolicy>();
    policy_mtd =  std::make_shared<TagCohPolicy>();

    dc_interface = new DfiTaggerDataCacheInterface(tag);
    outer = new DfiTaggerOuterPortBase(tag);

    tag_mem = new TagMemory_t("TagMemory");

    dfi_tagger = new DfiTagger(tt, mtt, mtd, 
    policy_tt, policy_mtt, policy_mtd, 
    outer, dc_interface, tag, "TC");

    auto* dfi_outer = dfi_tagger->get_outer();
    dfi_outer->connect(tag_mem,
      tag_mem->connect(dfi_outer->get_client(0)),
      tag_mem->connect(dfi_outer->get_client(1)),
      tag_mem->connect(dfi_outer->get_client(2)));

    acc_monitors = std::array<MonitorBase*,3>{
      new SimpleAccMonitor(),
      new SimpleAccMonitor(),
      new SimpleAccMonitor()
    };

    trace_monitor = new SimpleTracer();

    dfi_tagger->attach_monitor(trace_monitor, trace_monitor, trace_monitor);
    tag_mem->attach_monitor(trace_monitor);

    executor = new Executor_t(dc_interface);
  }

  ~TagCacheDriver() {
    delete executor;
    delete trace_monitor;
    for (auto& m: acc_monitors) {
      delete m;
    }
    delete dfi_tagger;
    delete tag_mem;
  }

  Executor_t& get_executor() {
    return *executor;
  }

};


int main (void ) {

  TagCacheDriver td;

  test_input(td.dc_interface);
  test_trace("test", td.get_executor());

  return 0;
}

void rw_test(DfiTaggerDataCacheInterface* dc_interface) {
  dc_interface->read_tag(0, nullptr, tagsize);
  dc_interface->read_tag(1, nullptr, tagsize);
  dc_interface->write_tag(0, 1, nullptr, tagsize);
  auto ret = dc_interface->read_tag(1, nullptr, tagsize);
  assert(ret == 1);
  dc_interface->write_tag(2, 0, nullptr, tagsize);
  ret = dc_interface->read_tag(0, nullptr, tagsize);
  assert(ret == 0);
}

void flush_test(DfiTaggerDataCacheInterface* dc_interface) {
  dc_interface->flush(0, nullptr);  
  rw_test(dc_interface);
  dc_interface->flush_cache(nullptr);
}

int test_input(DfiTaggerDataCacheInterface* dc_interface) {

  rw_test(dc_interface);
  flush_test(dc_interface);

  return 0;
}