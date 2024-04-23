#ifndef CM_CACHE_TAGCACHE_HPP
#define CM_CACHE_TAGCACHE_HPP

#include "cache/cache.hpp"
#include "cache/coherence.hpp"
#include "cache/metadata.hpp"
#include "cache/mi.hpp"

///
/// @brief Tag Configuration,
/// Should be a singleton.
/// BE WARN!!!
struct TagConfig {
 public:
  typedef struct {
    uint64_t base;              // base of this level
    uint64_t size;              // siz eof this level
    uint64_t tagsz;             // tag size
    uint64_t linesz;            // block size of this level
    uint64_t base_pre;          // base of previous level
    uint64_t linesz_pre;        // block size of previous level
    uint64_t ratio;             // mapping ratio
    uint64_t aoffset;           // offset used in address calculation
    uint64_t moffset;           // offset used in mask calculation
    uint64_t dmask;             // write data mask
    uint64_t amask;             // address mask for write mask calculation
  } data_t;

  TagConfig() {}
  std::vector<data_t> data;

private:
  uint64_t memsz;
  uint64_t membase;
  uint64_t wordsz;

  static uint64_t ilog2(uint64_t d) { uint64_t rv = 0; while(d >>= 1) rv++; return rv;}

 public:
  uint64_t tagbase;

  void record_mem(uint64_t membase_, uint64_t memsize_, uint64_t wordsz_, uint64_t tagsz_) {
    membase = membase_;
    memsz = memsize_;
    wordsz = wordsz_;
    if(data.size() == 0) data.resize(1);
    data[0].tagsz = tagsz_;
  }

  void record_tc(unsigned int level, uint64_t tagsz, uint64_t linesz) {
    if(data.size() <= level) data.resize(level+1);
    data[level].tagsz = tagsz;
    data[level].linesz = linesz;
  }

  void init() {
    for(unsigned int i=0; i<data.size(); i++) {
      data[i].base_pre = i==0 ? membase : data[i-1].base;
      data[i].linesz_pre = i==0 ? wordsz / 8 : data[i-1].linesz;
      data[i].ratio = data[i].linesz_pre * 8 / data[i].tagsz;
      data[i].size = (i==0 ? memsz : data[i-1].size)  / data[i].ratio;
      data[i].base = membase + memsz - data[i].size;
      data[i].aoffset = ilog2(data[i].ratio);
      data[i].moffset = ilog2(data[i].linesz_pre);
      data[i].dmask = ((uint64_t)1 << data[i].tagsz) - 1;
      data[i].amask = 64 / data[i].tagsz - 1;
    }
    tagbase = data[0].base;
  }

  // return per 64-bit words' start address
  uint64_t addr_conv(int i, uint64_t addr) const {
    return data[i].base + (((addr - data[i].base_pre) >> data[i].aoffset) & ~0x7);
  }

  /// called together with addr_conv, extract tag offset from raw address
  uint64_t tag_offset(int i, uint64_t addr) const {
    return ((addr >> data[i].moffset) & data[i].amask) * data[i].tagsz;
  }
  uint64_t mask(int i, uint64_t addr, size_t bytes) const {
    return (bytes <= 8 ? data[i].dmask :  (((uint64_t)1 << data[i].tagsz*(bytes/8)) - 1)) << tag_offset(i, addr);
  }
  uint64_t extract_tag(int i, uint64_t addr, uint64_t tag) const {
    return (tag >> tag_offset(i, addr)) & data[i].dmask;
  }
  uint64_t addr_conv_rev(int i, uint64_t addr) const {
    return data[i].base_pre + ((addr - data[i].base) << data[i].aoffset);
  }
  bool is_top(uint64_t addr) const {
    return addr >= data[data.size()-1].base;
  }
  int addr_tag_level(uint64_t addr) const {
    for (int i = data.size()-1; i>= 0; i--) {
      if (addr >= data[i].base) return i; 
    }
    return 0;
  }

  uint64_t get_tagsz (int i) const { return data[i].tagsz; }
};

////////////////////////////////// DFI Tagger Specific Policies ///////////////////////////

/// Simulating MI Policy, but drop support for probes
class TagCohPolicyBase : public CohPolicyBase {
private:
  static const uint32_t test_read_act = 5;
  static const uint32_t test_write_act = 6;

public:

  bool is_test_read(coh_cmd_t cmd) const   { return cmd.act == test_read_act;  }
  bool is_test_write(coh_cmd_t cmd) const  { return cmd.act == test_write_act; }

  constexpr coh_cmd_t cmd_for_test_read()  const { return {-1, acquire_msg, test_read_act};  }
  constexpr coh_cmd_t cmd_for_test_write() const { return {-1, acquire_msg, test_write_act}; }

/// The following protected members and functions are identical to MIPolicy<MT, false, false>
protected:
  using CohPolicyBase::outer;
  using CohPolicyBase::cmd_for_probe_release;
  using CohPolicyBase::cmd_for_probe_writeback;
  using CohPolicyBase::cmd_for_null;
  using CohPolicyBase::is_evict;

public:
  virtual ~TagCohPolicyBase() {}

  virtual coh_cmd_t cmd_for_outer_acquire(coh_cmd_t cmd) const {
    return outer->cmd_for_write();
  }

  virtual std::pair<bool, coh_cmd_t> access_need_sync(coh_cmd_t cmd, const CMMetadataBase *meta) const {
    return std::make_pair(true, cmd_for_probe_release(cmd.id));
  }

  virtual std::tuple<bool, bool, coh_cmd_t> access_need_promote(coh_cmd_t cmd, const CMMetadataBase *meta) const {
    return std::make_tuple(false, false, cmd_for_null());
  }

  virtual void meta_after_fetch(coh_cmd_t outer_cmd, CMMetadataBase *meta, uint64_t addr) const {
    meta->init(addr);
    assert(outer->is_fetch_write(outer_cmd) && meta->allow_write());
    meta->to_modified(-1);
  }

  virtual void meta_after_grant(coh_cmd_t cmd, CMMetadataBase *meta, CMMetadataBase *meta_inner) const {
    meta->to_modified(cmd.id);
    meta_inner->to_modified(-1);
  }

  virtual std::pair<bool,coh_cmd_t> probe_need_sync(coh_cmd_t cmd, const CMMetadataBase *meta) const {
    return std::make_pair(false, cmd_for_null());
  }

  virtual void meta_after_probe(coh_cmd_t outer_cmd, CMMetadataBase *meta, CMMetadataBase* meta_outer, int32_t inner_id, bool writeback) const {
    CohPolicyBase::meta_after_probe(outer_cmd, meta, meta_outer, inner_id, writeback);
    if(meta) {
      if(outer->is_evict(outer_cmd) || outer->is_downgrade(outer_cmd)) meta->to_invalid();
    }
  }

  virtual std::tuple<bool, bool, coh_cmd_t> flush_need_sync(coh_cmd_t cmd, const CMMetadataBase *meta, bool uncached) const {
    if (uncached) {
      if(meta){
        if(is_evict(cmd)) return std::make_tuple(true, true, cmd_for_probe_release());
        else              return std::make_tuple(true, true, cmd_for_probe_writeback());
      } else              return std::make_tuple(true, false, cmd_for_null());
    } else
      return std::make_tuple(false, false, cmd_for_null());
  }

};

typedef  TagCohPolicyBase TagCohPolicy;

typedef std::shared_ptr<TagCohPolicyBase> tag_policy_ptr;


////////////////////////////////// DFI Tagger Coherent Ports //////////////////////////////////

typedef uint64_t dfitag_t ;
typedef uint64_t shadow_addr_t;


///
/// @brief Outer port of DFI Tagger,
/// it controls the interaction with tag memory
///
class DfiTaggerOuterPortBase;


///
/// @brief Cache operation wrapper of CacheBase type
/// 
///
class DfiTaggerCacheActions;

///
/// @brief InnerPort of DFI Tagger
/// 
/// @todo
///   * decide implementations of acquire and writeback resposes
///   * implementation of connect()
///   * require a special Data Cache OuterPort class
class DfiTaggerInnerPortBase 
{
protected:
  DfiTaggerOuterPortBase* outer;
  std::array<std::shared_ptr<DfiTaggerCacheActions>,3> cache_actions;
  TagConfig & tg;
public:
  virtual void acquire_resp(uint64_t addr, CMDataBase *data_inner, CMMetadataBase *meta_inner, coh_cmd_t cmd, uint64_t *delay) {};
  virtual void writeback_resp(uint64_t addr, CMDataBase *data_inner, CMMetadataBase *meta_inner, coh_cmd_t cmd, uint64_t *delay) {};

public:
  DfiTaggerInnerPortBase(TagConfig& tg) : tg(tg) {}
  virtual ~DfiTaggerInnerPortBase() {}

  virtual void set_cache_actions(std::array<std::shared_ptr<DfiTaggerCacheActions>,3> &cas) ;
  virtual void set_outer(DfiTaggerOuterPortBase* o) {outer = o;}

  void connect(CohClientBase*c, bool uncached = false) {};
};

class DfiTaggerCacheActions 
{
  CacheBase* cache;
  DfiTaggerInnerPortBase* inner;
  OuterCohPortBase* outer;
  tag_policy_ptr policy;
protected:
  TagConfig & tg;
public:
  virtual void evict(CMMetadataBase* meta, CMDataBase* data, int32_t ai, uint32_t s, uint32_t w, uint64_t *delay);
  virtual std::tuple<CMMetadataBase*, CMDataBase*, uint32_t, uint32_t, uint32_t>
   replace_line(uint64_t addr, uint64_t *delay);
  virtual std::tuple<CMMetadataBase *, CMDataBase *, uint32_t, uint32_t, uint32_t, bool>
  access_line(uint64_t addr, coh_cmd_t cmd, uint64_t *delay);
  virtual void write_line(uint64_t addr, CMDataBase *data_inner, CMMetadataBase *meta_inner, coh_cmd_t cmd, uint64_t *delay);
  virtual void flush_line(uint64_t addr, coh_cmd_t cmd, uint64_t *delay);

public:
  DfiTaggerCacheActions(CacheBase* c, tag_policy_ptr p, TagConfig& tg) : cache(c), tg(tg), policy(p) {}
  virtual ~DfiTaggerCacheActions() {}

  CacheBase* get_cache() {return cache;}
  void set_inner(DfiTaggerInnerPortBase* i) {inner = i;}
  void set_outer(OuterCohPortBase* o) {outer = o;}
  tag_policy_ptr& get_policy() {return policy;}
};


///
/// @brief Inner port interface with upper data cache
/// 
///
class DfiTaggerDataCacheInterface : public DfiTaggerInnerPortBase
{

public:

  uint64_t normalize(uint64_t addr) ;

  virtual const dfitag_t read_tag(uint64_t addr, uint64_t *delay, size_t tagsz);
  
  virtual void write_tag(uint64_t addr, const dfitag_t tag, uint64_t *delay, size_t tagsz);

  DfiTaggerDataCacheInterface(TagConfig& tg) : DfiTaggerInnerPortBase(tg) {}
  virtual ~DfiTaggerDataCacheInterface(){}

  /// @brief Synchronization functions
  virtual void flush(uint64_t addr, uint64_t *delay) {};
  virtual void writeback(uint64_t addr, uint64_t *delay) {};
  virtual void writeback_invalidate(uint64_t *delay) {};
  virtual void flush_cache(uint64_t *delay) {};

private:
  using DfiTaggerInnerPortBase::acquire_resp;
  using DfiTaggerInnerPortBase::writeback_resp;
};


///
/// @brief Derived from OuterCohPortBase, as real outer port client
/// to interact with memory. Each corresponds to a cache_action.
/// 
///
class DfiTaggerOuterCohPortClient : public OuterCohPortUncached {
public:
  DfiTaggerOuterCohPortClient(policy_ptr policy) : OuterCohPortUncached(policy) {}
  virtual ~DfiTaggerOuterCohPortClient() {}
};

/// @todo
///   * decide implementations of acquire and writeback requests
///   * implementation of connect()
class DfiTaggerOuterPortBase 
{
  DfiTaggerInnerPortBase * inner;
  CohMasterBase* coh;
  std::array<std::shared_ptr<DfiTaggerCacheActions>,3> cache_actions;
  std::array<OuterCohPortBase*,3> clients;
protected:
  TagConfig & tg;
public:
  virtual void acquire_req(uint64_t addr, CMMetadataBase *meta, CMDataBase *data, coh_cmd_t outer_cmd, uint64_t *delay) ;
  virtual void writeback_req(uint64_t addr, CMMetadataBase *meta, CMDataBase *data, coh_cmd_t outer_cmd, uint64_t *delay) ;
  bool is_uncached() const {return false;};

public:
  DfiTaggerOuterPortBase( TagConfig& tg) :tg(tg) {}
  virtual ~DfiTaggerOuterPortBase() {
    for (int i = 0; i < 3; i++) {
      if (clients[i] != nullptr) {
        delete clients[i];
      }
      clients[i] = nullptr;
    }
  }

  void set_cache_actions(std::array<std::shared_ptr<DfiTaggerCacheActions>,3>& cas) ;
  void set_inner(DfiTaggerInnerPortBase* i) {inner = i;}

  OuterCohPortBase* get_client(int i) {return clients[i];}

  /// @todo Connect Coherence Master's policy with each instance of caches.
  void 	connect (CohMasterBase *h, std::pair< int32_t, policy_ptr > info_tt, std::pair< int32_t, policy_ptr > info_mtt, std::pair< int32_t, policy_ptr > info_mtd) {
    coh = h;
    assert(cache_actions[0] != nullptr); /// Ensure that each cache action has been initialized
    assert(clients[0] != nullptr); /// Ensure that each client has been initialized
    clients[0]->connect(h, info_tt);
    clients[1]->connect(h, info_mtt);
    clients[2]->connect(h, info_mtd);
  }
};


/// Wrapper Class for interaction with upper level data caches.

class DfiTagger 
{
protected:
  const std::string name ;
  std::array<CacheBase*,3> caches;
  std::array<std::shared_ptr<DfiTaggerCacheActions>,3> cache_actions;
  std::array<tag_policy_ptr,3> policies;

public:
  DfiTaggerOuterPortBase* outer;
  DfiTaggerInnerPortBase* inner;
  TagConfig & tg;

  enum Hierarchy {TT, MTT, MTD, NumOfHierarchy};

  auto& get_cache_actions() {return cache_actions;}
  auto& get_caches() {return caches;}

  DfiTagger(CacheBase* tt, CacheBase* mtt, CacheBase* mtd, 
    tag_policy_ptr tt_policy, tag_policy_ptr mtt_policy, tag_policy_ptr mtd_policy,
    DfiTaggerOuterPortBase* outer, DfiTaggerInnerPortBase* inner, TagConfig& tg, std::string name)
  : caches{tt, mtt, mtd}, policies{tt_policy, mtt_policy, mtd_policy}, outer(outer), inner(inner), tg(tg), name(name)
  {
    for (int i = 0; i < 3; i++) {
      cache_actions[i] = std::make_shared<DfiTaggerCacheActions>(caches[i], policies[i], tg);
    }
    outer->set_cache_actions(get_cache_actions());
    inner->set_cache_actions(get_cache_actions());
    inner->set_outer(outer);
    outer->set_inner(inner);
  }

  virtual ~DfiTagger() {
    delete outer;
    delete inner;
    for (auto c: caches) {
      delete c;
    }
  }

  auto* get_outer() {return outer;}
  auto* get_inner() {return inner;}

  void attach_monitor(MonitorBase* mon_tt, MonitorBase* mon_mtt, MonitorBase* mon_mtd) {
    caches[TT]->monitors->attach_monitor(mon_tt);
    caches[MTT]->monitors->attach_monitor(mon_mtt);
    caches[MTD]->monitors->attach_monitor(mon_mtd);
  } 
  void detach_monitor() { 
    for (auto c: caches) {
      c->monitors->detach_monitor();
    }
  }
};

class DfiTagAccessorBase {
public:
  virtual const dfitag_t read_tag(uint64_t index, uint64_t offset, size_t tagsz) = 0;
  virtual void write_tag(uint64_t index, uint64_t offset, const dfitag_t tag, size_t tagsz) = 0;
  virtual bool is_empty()= 0;
};

class Data64BTagAccessor : public DfiTagAccessorBase 
{
  TagConfig & tg;
  CMDataBase* data;

  static inline dfitag_t dmask(size_t tagsz) {
    return ((uint64_t)1 << tagsz) - 1;
  }
public:
  const dfitag_t read_tag(uint64_t index, uint64_t offset, size_t tagsz) override {
    return (data->read(index) >> offset) & dmask(tagsz);
  }
  void write_tag(uint64_t index, uint64_t offset, const dfitag_t tag, size_t tagsz) override {
    dfitag_t mask = dmask(tagsz) << offset;
    data->write(index, tag << offset, mask);
  }

  bool is_empty() override {
    bool emptiness = true; 
    for (int i = 0; i<8; i++) 
      emptiness &= (data->read(i) == 0); 
    return emptiness;
  }

  Data64BTagAccessor(CMDataBase* data, TagConfig & tg) : data(data), tg(tg) {}
  ~Data64BTagAccessor() {}
};





#endif // CM_CACHE_TAGCACHE_HPP