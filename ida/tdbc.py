import butil
import ida_typeinf
import idc
import tcontainers
import tutil

class db2lookup_state (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "db2lookup_state", ["BaseBytes"])
  def create_types (self, parameter_names, unique = True):
    size = int (parameter_names[0])
    vec = tutil.create_template_and_make_name (tcontainers.blz_vector(), [tutil.integral_for_bytes (size)])
    tutil.add_packed_type ( self.make_name (parameter_names),
                            """
                            int current_state_;
                            int current_id_;
                            %s blob;
                            char in_situ_buffer[%s];
                            """ % (vec, size * 1024),
                            unique)

class db2lookup (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "db2lookup", ["BaseBytes"])
  def create_types (self, parameter_names, unique = True):
    cdb_lookuper = tutil.maybe_make_dummy_type ('WowClientDB2_Base_Lookuper')
    state = tutil.create_template_and_make_name (db2lookup_state(), parameter_names)
    tutil.add_packed_type ( self.make_name (parameter_names),
                            '%s _; %s *lookup; _DWORD id;' % (state, cdb_lookuper),
                            unique)

# todo: this appears to merge two different types (see it used twice
# in WowClientDB2_Base), which don't seem to actually be the same :(
# Let's hope nobody uses these for relevant analysis...
db2lookup_8 = tutil.create_template_and_make_name (db2lookup(), ['8'])
db2lookup_16 = tutil.create_template_and_make_name (db2lookup(), ['16'])
cdb_lookuper = tutil.add_packed_type ('WowClientDB2_Base_Lookuper',
                                      """
                                      virtual _UNKNOWN* fun_0();
                                      virtual _UNKNOWN* fun_1();
                                      virtual _UNKNOWN* fun_2();
                                      virtual _UNKNOWN* fun_3();
                                      virtual _UNKNOWN* fun_4();
                                      virtual _UNKNOWN* (__fastcall *get_current)(%s *);
                                      virtual %s* find_first(%s*, _QWORD id); // todo: at least here db2lookup_state only
                                      virtual void find_next(%s*);
                                      virtual _UNKNOWN* fun_8();
                                      virtual _UNKNOWN* fun_9();
                                      virtual _UNKNOWN* fun_10();
                                      virtual %s* fun_11(%s *);
                                      virtual _UNKNOWN* fun_12();
                                      virtual _UNKNOWN* fun_13();

                                      char unknown_size;
                                      """ % (db2lookup_8,
                                             db2lookup_8, db2lookup_8,
                                             db2lookup_8,
                                             db2lookup_16, db2lookup_16))

DB2RecordCallback = tutil.maybe_make_dummy_type_with_known_size ('DB2RecordCallback', 16)
DB2TableEvent = tutil.maybe_make_dummy_type ('DB2TableEvent')
# note: NOT WCDB2B::, that triggers a bug in parsing in IDA, resulting in a WCDB2B::T rather than vector<WCDB2B::T>...
WowClientDB2_Base__IndexDataMap = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base_IndexDataMap', 40)
WowClientDB2_Base__UniqueIdxByInt = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base_UniqueIdxByInt', 40)
WowClientDB2_Base__UniqueIdxByString = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base_UniqueIdxByString', 40)
WowClientDB2_Base__AsyncSection = tutil.add_unpacked_type ('WowClientDB2_Base_AsyncSection',
                                                           """
                                                           void* m_WowClientDB2Instance; // == WowClientDB2_Base*?
                                                           void* asyncLoadClass;
                                                           __int64 field_10;
                                                           char m_loaded;
                                                           uint32_t field_1c;
                                                           void* sectionBufferPtr;
                                                           """)

wdc3_db2_header = tutil.add_packed_type('wdc3_db2_header',
                                        """
                                        uint32_t magic;
                                        uint32_t record_count;
                                        uint32_t field_count;
                                        uint32_t record_size;
                                        uint32_t string_table_size;
                                        uint32_t table_hash;
                                        uint32_t layout_hash;
                                        uint32_t min_id;
                                        uint32_t max_id;
                                        uint32_t locale;
                                        uint16_t flags;
                                        uint16_t id_index;
                                        uint32_t total_field_count;
                                        uint32_t bitpacked_data_offset;
                                        uint32_t lookup_column_count;
                                        uint32_t field_storage_info_size;
                                        uint32_t common_data_size;
                                        uint32_t pallet_data_size;
                                        uint32_t section_count;
                                        """)
field_storage_info = tutil.add_packed_type('field_storage_info',
                                           """
                                           uint16_t field_offset_bits;
                                           uint16_t field_size_bits;
                                           uint32_t additional_data_size;
                                           uint32_t storage_type;
                                           uint32_t bitpacking_offset_bits;
                                           uint32_t bitpacking_size_bits;
                                           uint32_t flags;
                                           """)
wdc3_section_header = tutil.add_packed_type('wdc3_section_header',
                                            """
                                            __int64 tact_key_hash;
                                            uint32_t file_offset;
                                            uint32_t record_count;
                                            uint32_t string_table_size;
                                            uint32_t offset_records_end;
                                            uint32_t id_list_size;
                                            uint32_t relationship_data_size;
                                            uint32_t offset_map_id_count;
                                            uint32_t copy_table_count;
                                            """)
field_structure = tutil.add_unpacked_type('field_structure',
                                          """
                                          uint16_t size;
                                          uint16_t offset;
                                          """)

dbc_string = tutil.add_unpacked_type ('dbc_string', 'uint32_t _;')
dbc_locstring = tutil.add_unpacked_type ('dbc_locstring', 'uint32_t _;')

DBMeta_intidx = tutil.add_unpacked_type('DBMeta_intidx',
                                        """
                                        int column;
                                        char use_null_column_content;
                                        __int64 null_column_content;
                                        """,
                                        False,
                                        0x10)


DBMeta_stridx = tutil.add_unpacked_type('DBMeta_stridx',
                                        """
                                        int column;
                                        char use_null_column_content;
                                        char const* null_column_content;
                                        """,
                                        False,
                                        0x10)

DBMeta = tutil.add_unpacked_type ('DBMeta',
                                   """
                                   const char* tableName;
                                   int fdid;
                                   int fieldCount;
                                   int record_size;
                                   int hotFixFieldCount;
                                   int id_column;
                                   char sparseTable;
                                   unsigned int* hotFixField_offsets;
                                   unsigned int* hotFixField_sizes;
                                   unsigned int* hotFixField_types;
                                   unsigned int* hotFixField_flags;
                                   unsigned int* fieldSizes;
                                   unsigned int* fieldTypes;
                                   unsigned int* fieldFlags;
                                   char flags_58;
                                   int tableHash;
                                   int sibling_tableHash;
                                   int layoutHash;
                                   char flags_68;
                                   int nbUniqueIdxByInt;
                                   int nbUniqueIdxByString;
                                   {intidxt}* uniqueIdxByInt;
                                   {stridxt}* uniqueIdxByString;
                                   char hasParentId;
                                   int parentIdFieldIndex;
                                   int parentIdFieldIndex_file;
                                   void* sortFunc;
                                   void* sortFuncIndirect;""".format(stridxt=DBMeta_stridx,intidxt=DBMeta_intidx))

WowClientDB2_Base = tutil.add_unpacked_type ('WowClientDB2_Base',
                                              """
                                              virtual void* dtor();
                                              virtual void* vf01();
                                              virtual void* vf02();
                                              virtual void* vf03();
                                              virtual void* vf04();
                                              virtual void* vf05();
                                              virtual void* vf06();
                                              virtual void* vf07();
                                              virtual void* vf08();
                                              virtual void* vf09();
                                              virtual void* vf10();
                                              virtual void* vf11();
                                              virtual void* vf12();
                                              virtual void* vf13();
                                              virtual void* vf14();
                                              virtual void* vf15();
                                              virtual void* vf16();
                                              virtual void* vf17();
                                              virtual void* vf18();
                                              virtual void* vf19();
                                              virtual void* vf20();
                                              virtual void* vf21();
                                              virtual void* vf22();
                                              virtual void* vf23();
                                              virtual void* vf24();
                                              virtual void* vf25();
                                              virtual void* vf26();
                                              virtual void* vf27();
                                              virtual void* vf28();
                                              virtual void* vf29();
                                              virtual void* vf30();
                                              virtual void* vf31();
                                              virtual void* vf32();
                                              virtual void* vf33();
                                              virtual void* vf34();
                                              virtual void* vf35();
                                              virtual void* vf36();
                                              virtual void* vf37();
                                              virtual void* vf38();
                                              virtual void* vf39();

                                              const {meta}* m_meta;
                                              {columnmeta} m_columnMeta;
                                              {vecunknown} palleteData;
                                              {vecunknown} palleteDataForIndexedArrays;
                                              {vecunknown} commonData;
                                              int field_70;
                                              int field_74;
                                              _QWORD field_78;
                                              __int64 field_80;
                                              __int64 m_pendingPatches_size;
                                              float field_90;
                                              int field_94;
                                              {lookuper}* m_parentLookup;
                                              {reccallbacks} recordCallbacks;
                                              {tableevents} tableEvents;
                                              _QWORD field_D0;
                                              _QWORD field_D8;
                                              _QWORD field_E0;
                                              float field_E8;
                                              int field_EC;
                                              {indexdatas} bucket_infos;
                                              {vecunknown} field_108;
                                              {filehdr}* m_fileHeader;
                                              {filesecthdr}* m_sectionHeaders;
                                              void* m_rawData;
                                              void* m_rawDataCopy;
                                              {lookuper}* lookuper;
                                              {idxbyints} uniqueidxbyint;
                                              {idxbystrs} uniqueidxbystring;
                                              {fields}* m_fields;
                                              {asyncsects} asyncSections;
                                              int field_198;
                                              int m_numFileRecords;
                                              int some_row_count1;
                                              int m_loadedRowsCnt;
                                              _DWORD maxID;
                                              _DWORD minID;
                                              __int64 field_1B0;
                                              _QWORD field_1B8;
                                              _QWORD field_1C0;
                                              int field_1C8;
                                              char dummy_pos_for_end_of_records;
                                              char isLoaded;
                                              char field_1CE;
                                              char m_uniqueIndicesValid;
                                              _BYTE field_1D0;
                                              char unknown_size;
                                              """.format(meta=DBMeta,
                                                         filehdr=wdc3_db2_header,
                                                         filesecthdr=wdc3_section_header,
                                                         fields=field_structure,
                                                         columnmeta=tutil.create_template_and_make_name (tcontainers.blz_vector(), [field_storage_info]),
                                                         vecunknown=tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                         lookuper=cdb_lookuper,
                                                         reccallbacks=tutil.create_template_and_make_name (tcontainers.blz_vector(), [DB2RecordCallback]),
                                                         tableevents=tutil.create_template_and_make_name (tcontainers.blz_vector(), [DB2TableEvent]),
                                                         indexdatas=tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__IndexDataMap]),
                                                         idxbyints=tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__UniqueIdxByInt]),
                                                         idxbystrs=tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__UniqueIdxByString]),
                                                         asyncsects=tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__AsyncSection])))

def make_db2meta(ea):
  ti = ida_typeinf.tinfo_t()
  ida_typeinf.parse_decl (ti, None, DBMeta + ' a;', 0)

  def dword_mem(name):
    m = ida_typeinf.udt_member_t()
    m.name = name
    if ti.find_udt_member (m, ida_typeinf.STRMEM_NAME) == -1:
      raise Exception ('unknown DBMeta member {}'.format (name))
    return butil.get_uint32(ea + m.offset // 8)
  def qword_mem(name):
    m = ida_typeinf.udt_member_t()
    m.name = name
    if ti.find_udt_member (m, ida_typeinf.STRMEM_NAME) == -1:
      raise Exception ('unknown DBMeta member {}'.format (name))
    return butil.get_uint64(ea + m.offset // 8)

  nameaddr = qword_mem ('tableName')
  name = butil.get_cstring (nameaddr).decode('utf-8')

  butil.mark_string (nameaddr, 'dbMeta_{}_tableName'.format(name))

  hfc = dword_mem('hotFixFieldCount')
  for f in ['hotFixField_offsets', 'hotFixField_sizes',
            'hotFixField_types', 'hotFixField_flags',]:
    butil.force_array( qword_mem(f),
                       'unsigned int const',
                       'dbMeta_{}_{}'.format(name, f),
                       hfc)

  fc = dword_mem('fieldCount')
  for f in ['fieldSizes', 'fieldTypes', 'fieldFlags']:
    butil.force_array( qword_mem(f),
                       'unsigned int const',
                       'dbMeta_{}_{}'.format(name, f),
                       fc)

  if dword_mem('nbUniqueIdxByInt'):
    num = dword_mem('nbUniqueIdxByInt')
    butil.force_array( qword_mem('uniqueIdxByInt'),
                       '{} const'.format (DBMeta_intidx),
                       'dbMeta_{}_uniqueIdxByInt'.format(name),
                       num)

  if dword_mem('nbUniqueIdxByString'):
    num = dword_mem('nbUniqueIdxByString')
    butil.force_array( qword_mem('uniqueIdxByString'),
                       '{} const'.format (DBMeta_stridx),
                       'dbMeta_{}_uniqueIdxByString'.format(name),
                       num)

  rec = tutil.maybe_make_dummy_type_with_known_size ('{}Rec'.format(name),
                                                     dword_mem ('record_size'))

  if qword_mem ('sortFunc'):
    fp = qword_mem ('sortFunc')
    butil.force_function(fp, 'bool f({rec} const*, {rec} const*)'.format(rec=rec), '{}::sort'.format(rec))
  if qword_mem ('sortFuncIndirect'):
    fp = qword_mem ('sortFuncIndirect')
    butil.force_function(fp, 'bool f({rec} const* const*, {rec} const* const*)'.format(rec=rec), '{}::sortIndirect'.format(rec))

  butil.force_variable (ea, '{} const'.format(DBMeta), 'dbMeta_{}'.format(name))

  return name
