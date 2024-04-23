#include "cache/memory.hpp"
#include "util/cache_type.hpp"
#include "cache/tagcache.hpp"


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

typedef SimpleMemoryModel<TagMemory_data_t, TagMemory_delay_t> TagMemory_t;

int main (void ) {


  TagConfig tag;
  tag.record_mem(0, memsize , 64, tagsize);
  tag.record_tc(0,tagsize,cacheblocksize); /// Tag Table
  tag.record_tc(1,1,cacheblocksize); /// Meta Tag Table
  tag.record_tc(2,1,cacheblocksize); /// Meta Tag Directory

  tag.init();

  CacheBase* tt = new TT_cache_t("TT") ;
  CacheBase* mtt = new MTT_cache_t("MTT");
  CacheBase* mtd = new MTD_cache_t("MTD");

  std::shared_ptr<TagCohPolicy> policy_tt =   std::make_shared<TagCohPolicy>();
  std::shared_ptr<TagCohPolicy> policy_mtt =  std::make_shared<TagCohPolicy>();
  std::shared_ptr<TagCohPolicy> policy_mtd =  std::make_shared<TagCohPolicy>();

  DfiTaggerDataCacheInterface* dc_interface =
    new DfiTaggerDataCacheInterface(tag);
  DfiTaggerOuterPortBase* outer =
    new DfiTaggerOuterPortBase(tag);

  TagMemory_t* tag_mem = new TagMemory_t("TagMemory");

  DfiTagger dfi_tagger = DfiTagger(tt, mtt, mtd, 
    policy_tt, policy_mtt, policy_mtd, 
    outer, dc_interface, tag, "TC");

  auto* dfi_outer = dfi_tagger.get_outer();
  dfi_outer->connect(tag_mem,
    tag_mem->connect(dfi_outer->get_client(0)),
    tag_mem->connect(dfi_outer->get_client(1)),
    tag_mem->connect(dfi_outer->get_client(2)));

  /// @todo Initialize tag cache monitor
  std::array<MonitorBase*,3> acc_monitors {
    new SimpleAccMonitor(),
    new SimpleAccMonitor(),
    new SimpleAccMonitor()
  };

  auto trace_monitor = new SimpleTracer(true);

  // dfi_tagger.attach_monitor(acc_monitors[0], acc_monitors[1], acc_monitors[2]);
  dfi_tagger.attach_monitor(trace_monitor, trace_monitor, trace_monitor);

  test_input(dc_interface);

  delete trace_monitor;

  for (auto& m: acc_monitors) {
    delete m;
  }

  delete tag_mem;

  return 0;
}

int test_input(DfiTaggerDataCacheInterface* dc_interface) {

  dc_interface->read_tag(0, nullptr, tagsize);
  dc_interface->read_tag(1, nullptr, tagsize);
  
  return 0;
}