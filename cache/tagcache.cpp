#include "cache/tagcache.hpp"

/// TODO: implement
uint64_t DfiTaggerDataCacheInterface::normalize(uint64_t addr) { 
  return addr ; 
}

/// TODO: implement
const DfiTaggerDataCacheInterface::dfitag_t
DfiTaggerDataCacheInterface::read_tag(uint64_t addr, uint64_t *delay, size_t tagsz) {
  return 0;
}

/// TODO: implement
void DfiTaggerDataCacheInterface::write_tag(uint64_t addr, dfitag_t tag, uint64_t *delay, size_t tagsz) {

}

