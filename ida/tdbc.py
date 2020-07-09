import tutil
import tcontainers

# todo: these probably only exist with the ptr+id, so merge.
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
cdb_lookuper = tutil.maybe_make_dummy_type ('WowClientDB2_Base_Lookuper')
vt_cdb_lookuper = tutil.add_packed_type ('vtable$%s' % (cdb_lookuper),
                                         """
                                         _UNKNOWN* fun_0;
                                         _UNKNOWN* fun_1;
                                         _UNKNOWN* fun_2;
                                         _UNKNOWN* fun_3;
                                         _UNKNOWN* fun_4;
                                         _UNKNOWN* (__fastcall *get_current)(%s*, %s *);
                                         %s *(__fastcall *find_first)(%s*, %s *, _QWORD id);
                                         void (__fastcall *find_next)(%s*, %s *);
                                         _UNKNOWN* fun_8;
                                         _UNKNOWN* fun_9;
                                         _UNKNOWN* fun_10;
                                         %s *(__fastcall *fun_11)(%s *, %s *);
                                         _UNKNOWN* fun_12;
                                         _UNKNOWN* fun_13;
                                         """ % (cdb_lookuper, db2lookup_8,
                                                db2lookup_8, cdb_lookuper, db2lookup_8,
                                                cdb_lookuper, db2lookup_8,
                                                db2lookup_16, cdb_lookuper, db2lookup_16))
cdb_lookuper = tutil.add_packed_type ('%s' % (cdb_lookuper),
                                      '%s *vtable; char unknown_size;' % (vt_cdb_lookuper))

DB2RecordCallback = tutil.maybe_make_dummy_type_with_known_size ('DB2RecordCallback', 16)
DB2TableEvent = tutil.maybe_make_dummy_type ('DB2TableEvent')
WowClientDB2_Base__IndexDataMap = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base::IndexDataMap', 40)
WowClientDB2_Base__UniqueIdxByInt = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base::UniqueIdxByInt', 40)
WowClientDB2_Base__UniqueIdxByString = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base::UniqueIdxByString', 40)
WowClientDB2_Base__AsyncSection = tutil.maybe_make_dummy_type_with_known_size ('WowClientDB2_Base::AsyncSection', 40)

DBMeta = tutil.add_unpacked_type ('DBMeta',
                                   """
                                   const char *tableName;
                                   int fdid;
                                   int file_columns;
                                   int field_10;
                                   int hotFixFieldCount;
                                   int field_18;
                                   char sparseTable;
                                   int *field_20;
                                   void *field_28;
                                   void *field_30;
                                   void *field_38;
                                   void *field_40;
                                   void *field_48;
                                   void *field_50;
                                   _BYTE gap58[4];
                                   int m_tableHash;
                                   int field_60;
                                   int layoutHash;
                                   int field_68;
                                   int nbUniqueIdxByInt;
                                   int nbUniqueIdxByString;
                                   int field_74;
                                   void *field_78;
                                   int field_80;
                                   int field_84;
                                   int field_88;
                                   int field_8C;
                                   int field_90;
                                   int field_94;
                                   void *field_98;
                                   void *field_A0;""")

WowClientDB2_Base = tutil.add_unpacked_type ('WowClientDB2_Base2',
                                              """
                                              void *vtable; // todo
                                              const %s *m_meta;
                                              %s m_columnMeta;
                                              %s field_28;
                                              %s field_40;
                                              %s field_58;
                                              __int64 field_70;
                                              _QWORD field_78;
                                              __int64 field_80;
                                              __int64 m_pendingPatches_size;
                                              float field_90;
                                              int field_94;
                                              %s *m_parentLookup;
                                              %s recordCallbacks;
                                              %s tableEvents;
                                              _QWORD field_D0;
                                              _QWORD field_D8;
                                              _QWORD field_E0;
                                              float field_E8;
                                              int field_EC;
                                              %s bucket_infos;
                                              %s field_108;
                                              void *m_fileHeader;
                                              void *field_128;
                                              void *m_rawData;
                                              void *m_rawDataCopy;
                                              %s *lookuper;
                                              %s uniqueidxbyint;
                                              %s uniqueidxbystring;
                                              void *field_178;
                                              %s asyncSections;
                                              int field_198;
                                              int m_numFileRecords;
                                              int some_row_count1;
                                              int some_row_count2;
                                              _DWORD maxID;
                                              _DWORD minID;
                                              __int64 field_1B0;
                                              _QWORD field_1B8;
                                              _QWORD field_1C0;
                                              int field_1C8;
                                              char dummy_pos_for_end_of_records;
                                              char isLoaded;
                                              char field_1CE;
                                              char field_1CF;
                                              _BYTE field_1D0;
                                              char unknown_size;
                                              """ % ( DBMeta,
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                      cdb_lookuper,
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [DB2RecordCallback]),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [DB2TableEvent]),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__IndexDataMap]),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), ['_UNKNOWN']),
                                                      cdb_lookuper,
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__UniqueIdxByInt]),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__UniqueIdxByString]),
                                                      tutil.create_template_and_make_name (tcontainers.blz_vector(), [WowClientDB2_Base__AsyncSection])))
