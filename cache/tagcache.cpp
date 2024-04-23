#include "cache/tagcache.hpp"

static inline int word_idx(uint64_t addr) { return (addr >> 3) & 0x7; }

void 
DfiTaggerInnerPortBase::set_cache_actions(std::array<std::shared_ptr<DfiTaggerCacheActions>,3> &cas){
  cache_actions = cas;
  for (auto& ca: cas)
    ca->set_inner(this);
}

void 
DfiTaggerOuterPortBase::set_cache_actions(std::array<std::shared_ptr<DfiTaggerCacheActions>,3>& cas) {
  cache_actions = cas; 
  for (int i = 0; i < 3; i++) {
    clients[i] = new DfiTaggerOuterCohPortClient(cas[i]->get_policy());
    cas[i]->set_outer(clients[i]);
  }
}

void 
DfiTaggerOuterPortBase::acquire_req(uint64_t addr, CMMetadataBase *meta, CMDataBase *data, coh_cmd_t outer_cmd, uint64_t *delay) {
  coh->acquire_resp(addr, data, meta->get_outer_meta(), outer_cmd, delay);
}

void 
DfiTaggerOuterPortBase::writeback_req(uint64_t addr, CMMetadataBase *meta, CMDataBase *data, coh_cmd_t outer_cmd, uint64_t *delay) {
  
}

///
/// @brief 
/// 
/// @param addr Raw data cache address
/// @return uint64_t Truncated address: ( addr >> IOff ) << IOff
///
uint64_t DfiTaggerDataCacheInterface::normalize(uint64_t addr) { 
  return addr & ~0x3full; 
}

  /***
  * Modelling meta tag table operations:
  When handling an incoming tag table read access, 
  the Tracker checks whether 
  the MTT cache and the tag cache has a matching entry. 
  If the Tracker fails to find a matching tag table entry, 
  it checks the MTD and the matching MTT entry 
  (loaded into MTT cache if does not exist) 
  to see if the corresponding tag table entry is all zero.
  * MTT handles access to the MTT in the memory in parallel with the tag table.
  * Searching in order TT -> MTD -> MTT
  * hook_read is a fetch when (meta != nullptr) && !hit
  see: http://ieeexplore.ieee.org/document/7546472/
  */
const dfitag_t
DfiTaggerDataCacheInterface::read_tag(uint64_t addr, uint64_t *delay, size_t tagsz) {
  addr = normalize(addr);
  const shadow_addr_t stt = tg.addr_conv(0, addr);
  const uint64_t stt_off = tg.tag_offset(0, addr);
  const uint64_t stt_idx = word_idx(stt); 
  const size_t stt_tgsz = tg.get_tagsz(0);
  const shadow_addr_t smtt = tg.addr_conv(1, stt);
  const uint64_t smtt_off = tg.tag_offset(1, stt);
  const uint64_t smtt_idx = word_idx(smtt);
  const size_t smtt_tgsz = tg.get_tagsz(1);
  const shadow_addr_t smtd = tg.addr_conv(2, smtt);
  const uint64_t smtd_off = tg.tag_offset(2, smtt);
  const uint64_t smtd_idx = word_idx(smtd);
  const size_t smtd_tgsz = tg.get_tagsz(2);
  const auto TT = DfiTagger::TT;
  const auto MTT = DfiTagger::MTT;
  const auto MTD = DfiTagger::MTD;

  Data64B dummy_tt;
  Data64B dummy_mtt;

  /// Declarations of mutables
  CMMetadataBase* meta_tt, *meta_mtt, *meta_mtd;
  CMDataBase* data_tt, *data_mtt, *data_mtd;
  uint32_t ai_tt, ai_mtt, ai_mtd;
  uint32_t s_tt, s_mtt, s_mtd;
  uint32_t w_tt, w_mtt, w_mtd;
  bool hit_tt, hit_mtt, hit_mtd;

  /// Checks wether the MTT and Tag Table has a matching entry

#define TEST_READ_ONLY(HRCY,postfix) \
  auto cmd_read_ ## postfix = cache_actions[HRCY]->get_policy()->cmd_for_test_read(); \
  std::tie(meta_ ## postfix, data_ ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix) \
    = cache_actions[HRCY]->access_line(s ## postfix, cmd_read_ ## postfix, delay); \

#define FORCE_READ_ONLY(HRCY,postfix) \
  auto cmd_forced_read_ ## postfix = cache_actions[HRCY]->get_policy()->cmd_for_read(); \
  std::tie(meta_ ## postfix, data_ ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix) \
    = cache_actions[HRCY]->access_line(s ## postfix, cmd_forced_read_ ## postfix, delay); \

#define HOOK_READ_ONLY(HRCY,postfix) \
  cache_actions[HRCY]->get_cache()->hook_read(s ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix, meta_ ## postfix, data_ ## postfix, delay); \

#define TEST_READ(HRCY,postfix) \
  TEST_READ_ONLY(HRCY,postfix);HOOK_READ_ONLY(HRCY,postfix)

#define FORCE_READ(HRCY,postfix) \
  FORCE_READ_ONLY(HRCY,postfix);HOOK_READ_ONLY(HRCY,postfix)

#define CREATE_ONLY(HRCY,postfix) \
  std::tie(meta_ ## postfix, data_ ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix) \
    = cache_actions[HRCY]->create_line(s ## postfix, &dummy_ ## postfix, delay);

  /// Searching order: Bottom (TT) -> Top (MTD) -> Middle (MTT)

  TEST_READ(TT,tt);
  TEST_READ(MTT,mtt);


  /// do nothing if both hit
  if (hit_tt && hit_mtt) {}
  /// If the Tracker fails to find a matching tag table entry,
  /// it checks the MTD and the matching MTT entry
  else if (!hit_tt || !hit_mtt) {
    FORCE_READ(MTD, mtd);

  /// @todo Figure out whether we should load MTT if corresponding MTD is 0? I guess not.
  /// @todo Need to restrict data_mtd of Derived type of Data64B;
  /// If the MTT entry does not exist, load it
    auto data_tag_mtd = Data64BTagAccessor(data_mtd, tg);
    uint64_t mapbit_mtd = data_tag_mtd.read_tag(smtd_idx, smtd_off, smtd_tgsz);

    if (!hit_mtt && mapbit_mtd != 0) {
      FORCE_READ_ONLY(MTT, mtt); /// just perform fetching
    }
    else if (!hit_mtt && mapbit_mtd == 0) {
      CREATE_ONLY(MTT, mtt);
      if (meta_mtt == nullptr) {}
    }

  /// if the corresponding tag table entry is all zero,
  /// handle the incoming tag table access without really fetching
  /// the tag table entry from memory
    auto data_tag_mtt = Data64BTagAccessor(data_mtt, tg);
    uint64_t mapbit_mtt = data_tag_mtt.read_tag(smtt_idx, smtt_off, smtt_tgsz);

  /// else, fetch the tag table entry from memory
  /// @todo Figure out if there should be a FORCE_READ_ONLY instead of FORCE_READ
    if (!hit_tt && mapbit_mtt != 0) {
      FORCE_READ_ONLY(TT, tt);
    }
    else if (!hit_tt && mapbit_mtt == 0) {
      CREATE_ONLY(TT, tt);
    }

  }

  auto data_tag_tt = Data64BTagAccessor(data_tt, tg);
  uint64_t tag_tt = data_tag_tt.read_tag(stt_idx, stt_off, stt_tgsz);

  return tag_tt;

}

  /***
  * Modelling meta tag table operations:
  After updating the tag table entry and the MTT entry, 
  the Tracker checks if 
  it can clear the corresponding MTT entry bit and MTD bit. 
  In particular, the Tracker clears the corresponding bit in MTT entry 
  if the updated tag table entry is filled with zeros, 
  and clears the MTD bit if the MTT entry is filled with zeros.
  see: http://ieeexplore.ieee.org/document/7546472/
  */
void DfiTaggerDataCacheInterface::write_tag(uint64_t addr, dfitag_t tag, uint64_t *delay, size_t tagsz) {
  addr = normalize(addr);
  const shadow_addr_t stt = tg.addr_conv(0, addr);
  const uint64_t stt_off = tg.tag_offset(0, addr);
  const uint64_t stt_idx = word_idx(stt); 
  const size_t stt_tgsz = tg.get_tagsz(0);
  const shadow_addr_t smtt = tg.addr_conv(1, stt);
  const uint64_t smtt_off = tg.tag_offset(1, stt);
  const uint64_t smtt_idx = word_idx(smtt);
  const size_t smtt_tgsz = tg.get_tagsz(1);
  const shadow_addr_t smtd = tg.addr_conv(2, smtt);
  const uint64_t smtd_off = tg.tag_offset(2, smtt);
  const uint64_t smtd_idx = word_idx(smtd);
  const size_t smtd_tgsz = tg.get_tagsz(2);
  const auto TT = DfiTagger::TT;
  const auto MTT = DfiTagger::MTT;
  const auto MTD = DfiTagger::MTD;

  Data64B dummy_tt;
  Data64B dummy_mtt;

  /// Declarations of mutables
  CMMetadataBase* meta_tt, *meta_mtt, *meta_mtd;
  CMDataBase* data_tt, *data_mtt, *data_mtd;
  uint32_t ai_tt, ai_mtt, ai_mtd;
  uint32_t s_tt, s_mtt, s_mtd;
  uint32_t w_tt, w_mtt, w_mtd;
  bool hit_tt, hit_mtt, hit_mtd;

#define TEST_WRITE_ONLY(HRCY,postfix) \
  auto cmd_write_ ## postfix = cache_actions[HRCY]->get_policy()->cmd_for_test_write(); \
  std::tie(meta_ ## postfix, data_ ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix) \
    = cache_actions[HRCY]->access_line(s ## postfix, cmd_write_ ## postfix, delay); \

#define FORCE_WRITE_ONLY(HRCY,postfix) \
  auto cmd_forced_write_ ## postfix = cache_actions[HRCY]->get_policy()->cmd_for_write(); \
  std::tie(meta_ ## postfix, data_ ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix) \
    = cache_actions[HRCY]->access_line(s ## postfix, cmd_forced_write_ ## postfix, delay); \

#define HOOK_WRITE_ONLY(HRCY,postfix) \
  meta_ ## postfix -> to_dirty(); \
  cache_actions[HRCY]->get_cache()->hook_write(s ## postfix, ai_ ## postfix, s_ ## postfix, w_ ## postfix, hit_ ## postfix, false, meta_ ## postfix, data_ ## postfix, delay); \

  /// Search for tag table entry first
  /// which will introduce some read accesses.

  TEST_WRITE_ONLY(TT, tt);
  HOOK_READ_ONLY(TT, tt); /// This write access only tests if the tag table entry is valid,
                          /// so categorize it as read access.

  TEST_READ(MTT, mtt);  /// Together with hook_read

  FORCE_READ(MTD, mtd); /// Together with hook_read

  /// Load entry first:
  /// In case both hit, do nothing
  if (hit_tt && hit_mtt) {}
  /// Otherwise, perform similar operations as read_tag
  else if (!hit_tt && !hit_mtt) {
    auto data_mtd_tag = Data64BTagAccessor(data_mtd, tg);
    uint64_t mapbit_mtd = data_mtd_tag.read_tag(smtd_idx, smtd_off, smtd_tgsz);
    if (!hit_mtd && mapbit_mtd != 0) {
      FORCE_READ_ONLY(MTT, mtt);  /// just perform fetching
    }
    else if (!hit_mtd && mapbit_mtd == 0) {
      CREATE_ONLY(MTT, mtt);
    }

    auto data_mtt_tag = Data64BTagAccessor(data_mtt, tg);
    uint64_t mapbit_mtt = data_mtt_tag.read_tag(smtt_idx, smtt_off, smtt_tgsz);
    if (!hit_mtt && mapbit_mtt != 0) {
      FORCE_WRITE_ONLY(TT, tt);  /// hook_write moved to position after actual write
    }
    else if (!hit_mtt && mapbit_mtt == 0) {
      CREATE_ONLY(TT, tt);
    }
  }

  /// loading complete, perform writing
  auto data_tt_tag = Data64BTagAccessor(data_tt, tg);
  bool data_tt_empty_old = data_tt_tag.is_empty();
  data_tt_tag.write_tag(stt_idx, stt_off, tag, stt_tgsz);
  bool data_tt_empty_new = data_tt_tag.is_empty();
  HOOK_WRITE_ONLY(TT, tt);

  /// In case data_tt_tag 's emptiness changed, update entries in MTT and MTD
  if (data_tt_empty_new == data_tt_empty_old) return ;

  auto data_mtt_tag = Data64BTagAccessor(data_mtt, tg);
  bool data_mtt_empty_old = data_mtt_tag.is_empty();
  data_mtt_tag.write_tag(smtt_idx, smtt_off, !data_tt_empty_new, smtt_tgsz);
  bool data_mtt_empty_new = data_mtt_tag.is_empty();
  HOOK_WRITE_ONLY(MTT, mtt);

  if (data_mtt_empty_new == data_mtt_empty_old) return ;

  auto data_mtd_tag = Data64BTagAccessor(data_mtd, tg);
  data_mtd_tag.write_tag(smtd_idx, smtd_off, !data_mtt_empty_new, smtd_tgsz);
  HOOK_WRITE_ONLY(MTD, mtd);

#undef HOOK_WRITE_ONLY
#undef FORCE_WRITE_ONLY
#undef TEST_WRITE_ONLY
#undef CREATE_ONLY
#undef FORCE_READ
#undef TEST_READ
#undef HOOK_READ_ONLY
#undef FORCE_READ_ONLY
#undef TEST_READ_ONLY
}

///
/// @brief Similar to InnerCohPortUncached::evict, but dropped sync logic
/// 
/// @param meta 
/// @param data 
/// @param ai 
/// @param s 
/// @param w 
/// @param delay 
///
void DfiTaggerCacheActions::evict(CMMetadataBase* meta, CMDataBase* data, int32_t ai, uint32_t s, uint32_t w, uint64_t *delay) {
  auto addr = meta->addr(s);
  assert(cache->hit(addr));
  auto writeback = policy->writeback_need_writeback(meta, outer->is_uncached());
  if (writeback.first) outer->writeback_req(addr, meta, data, writeback.second, delay);
  policy->meta_after_evict(meta);
  cache->hook_manage(addr, ai, s, w, true, true, writeback.first, meta, data, delay);
}


///
/// @brief Identical to InnerCohPortUncached::replace_line
/// 
/// @param addr 
/// @param delay 
/// @return std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t> 
///
std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t>
DfiTaggerCacheActions::replace_line(uint64_t addr, uint64_t *delay) {
  uint32_t ai, s, w;
  CMMetadataBase *meta;
  CMDataBase *data;
  cache->replace(addr, &ai, &s, &w);
  std::tie(meta, data) = cache->access_line(ai, s, w);
  if(meta->is_valid()) evict(meta, data, ai, s, w, delay);
  return std::make_tuple(meta, data, ai, s, w);
}


///
/// @brief Similar to InnerCohPortUncached::access_line, but drop sync logic
/// 
/// @param addr 
/// @param cmd 
/// @param delay 
/// @return std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t, bool> 
///
std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t, bool>
DfiTaggerCacheActions::access_line(uint64_t addr, coh_cmd_t cmd, uint64_t *delay) {
  uint32_t ai=0, s=0, w=0;
  CMMetadataBase *meta = nullptr;
  CMDataBase *data = nullptr;
  bool hit = cache->hit(addr, &ai, &s, &w);
  if(hit) {
    std::tie(meta, data) = cache->access_line(ai, s, w);
  } else if (policy->is_test_read(cmd) || policy->is_test_write(cmd)) {
    /// miss but not fetch:
    /// do nothing. Just return.
  } else { // miss
    std::tie(meta, data, ai, s, w) = replace_line(addr, delay);
    coh_cmd_t outer_acquire = policy->cmd_for_outer_acquire(cmd); 
    outer->acquire_req(addr, meta, data, outer_acquire, delay); // fetch the missing block
    /// @todo Decide whether to set the hit bit when doing fetch access
  }

  return std::make_tuple(meta, data, ai, s, w, hit);
}


void DfiTaggerCacheActions::write_line(uint64_t addr, CMDataBase *data_inner, CMMetadataBase *meta_inner, coh_cmd_t cmd, uint64_t *delay) {
  auto [meta, data, ai, s, w, hit] = access_line(addr, cmd, delay);
  assert(hit || cmd.id == -1); // must hit if the inner is cached
  if(data_inner) data->copy(data_inner);
  policy->meta_after_release(cmd, meta, meta_inner);
  assert(meta_inner);
  bool is_release = true;
  cache->hook_write(addr, ai, s, w, hit, is_release, meta, data, delay);
}

std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t>
DfiTaggerCacheActions::create_line(uint64_t addr, CMDataBase* data_impl, uint64_t *delay) {
  auto [meta, data, ai, s, w] = replace_line(addr, delay);
  if(data_impl) data->copy(data_impl);
  policy->meta_after_create(meta, addr);
  return std::make_tuple(meta, data, ai, s, w);
}

/// @todo is this useful in Tag Cache ?
void DfiTaggerCacheActions::flush_line(uint64_t addr, coh_cmd_t cmd, uint64_t *delay) {
  
}