#include "cache/memory.hpp"
#include "util/cache_type.hpp"
#include "cache/tagcache.hpp"


int test_input(DfiTaggerDataCacheInterface* dc_interface);

int main (void ) {
  const uint64_t memsize = (16lu << 30); /// 16GiB Memory Region
  const uint64_t tagsize = 2;
  const uint64_t cacheblocksize = 64;
  const int levels = 3; // fixed.
  const int nSet = 32;
  const int nWay = 8;

  TagConfig tag;
  tag.record_mem(0, memsize , 64, tagsize);
  tag.record_tc(0,tagsize,cacheblocksize); /// Tag Table
  tag.record_tc(1,1,cacheblocksize); /// Meta Tag Table
  tag.record_tc(2,1,cacheblocksize); /// Meta Tag Directory

  tag.init();

  CacheBase* tt = nullptr;
  CacheBase* mtt = nullptr;
  CacheBase* mtd = nullptr;

  DfiTaggerDataCacheInterface* dc_interface;
  DfiTaggerOuterPortBase* outer;

  DfiTagger dfi_tagger = DfiTagger(tt, mtt, mtd, outer, dc_interface, tag, "TC");

  /// TODO: Initialize tag cache monitor

  test_input(dc_interface);

  return 0;
}

int test_input(DfiTaggerDataCacheInterface* dc_interface) {
  return 0;
}