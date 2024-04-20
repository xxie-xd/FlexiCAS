#include "cache/memory.hpp"
#include "util/cache_type.hpp"
#include "cache/tagcache.hpp"


int test_input(DfiTaggerDataCacheInterface* dc_interface);

int main (void ) {
  const uint64_t memsize = (16lu << 30); /// 16GiB Memory Region
  const uint64_t tagsize = 2;
  const uint64_t cacheblocksize = 64;
  const int levels = 3; // fixed.

  TagConfig tag;
  tag.record_mem(0, memsize , 64, tagsize);
  tag.record_tc(0,tagsize,cacheblocksize); /// Tag Table
  tag.record_tc(1,1,cacheblocksize); /// Meta Tag Table
  tag.record_tc(2,1,cacheblocksize); /// Meta Tag Directory

  tag.init();

  const int TTIW = 3; // ilog2(8)
  const int TTNW = 16;
  const int TTIOff = 6; // ilog2(64)
  
  typedef MetadataMI TT_metadata_t;
  typedef Data64B TT_data_t;
  typedef IndexNorm<TTIW,TTIOff> TT_indexer_t;
  typedef ReplaceLRU<TTIW,TTNW,true> TT_replacer_t;
  typedef void TT_delay_t;

  typedef CacheNorm<TTIW,TTNW,TT_metadata_t,TT_data_t,TT_indexer_t, TT_replacer_t, TT_delay_t, false> TT_cache_t ;

  const int MTTIW = 3; // ilog2(8)
  const int MTTNW = 16;
  const int MTTIOff = 6; // ilog2(64)

  typedef MetadataMI MTT_metadata_t;
  typedef Data64B MTT_data_t;
  typedef IndexNorm<MTTIW,MTTIOff> MTT_indexer_t;
  typedef ReplaceLRU<MTTIW,MTTNW,true> MTT_replacer_t;
  typedef void MTT_delay_t;

  typedef CacheNorm<MTTIW,MTTNW,MTT_metadata_t,MTT_data_t,MTT_indexer_t, MTT_replacer_t, MTT_delay_t, false> MTT_cache_t ;

  const int MTDIW = 0; // ilog2(1)
  const int MTDNW = 8;
  const int MTDIOff = 6; // ilog2(64)

  typedef MetadataMI MTD_metadata_t;
  typedef Data64B MTD_data_t;
  typedef IndexNorm<MTDIW,MTDIOff> MTD_indexer_t;
  typedef ReplaceLRU<MTDIW,MTDNW,true> MTD_replacer_t;
  typedef void MTD_delay_t;

  typedef CacheNorm<MTDIW,MTDNW,MTD_metadata_t,MTD_data_t,MTD_indexer_t, MTD_replacer_t, MTD_delay_t, false> MTD_cache_t ;


  CacheBase* tt = new TT_cache_t("TT") ;
  CacheBase* mtt = new MTT_cache_t("MTT");
  CacheBase* mtd = new MTD_cache_t("MTD");

  DfiTaggerDataCacheInterface* dc_interface =
    new DfiTaggerDataCacheInterface(tag);
  DfiTaggerOuterPortBase* outer =
    new DfiTaggerOuterPortBase(tag);

  DfiTagger dfi_tagger = DfiTagger(tt, mtt, mtd, outer, dc_interface, tag, "TC");

  /// @todo Initialize tag cache monitor

  test_input(dc_interface);

  return 0;
}

int test_input(DfiTaggerDataCacheInterface* dc_interface) {
  return 0;
}