import tutil

class blz_vector (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::vector", ["T"])
  def create_types (self, parameter_names, unique = True):
    p2 = tutil.add_packed_type ( "_2_blz_vector",
                                 "unsigned long long m_size; unsigned long long m_capacity;") # todo: m_capacity is 63+1 bit m_capacity+m_capacity_is_embedded
    tutil.add_packed_type ( self.make_name (parameter_names),
                            "%s* m_elements; %s _2;" % (parameter_names[0], p2),
                            unique)

blz_string = tutil.add_packed_type ('blz::string', # todo: m_capacity is 63+1 bit m_capacity+m_capacity_is_embedded
                                    """
                                    char* m_elements;
                                    unsigned long long m_size;
                                    unsigned long long m_capacity; 
                                    char m_storage[16];""")

class blz_pair (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::pair", ["T", "U"])
  def create_types (self, parameter_names, unique = True):
    tutil.add_unpacked_type ( self.make_name (parameter_names),
                              '''
                              {T} first;
                              {U} second;'''.format (T=parameter_names[0], U=parameter_names[1]),
                              unique)

class blz_chained_hash_node (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::chained_hash_node", ["Value"])
  def create_types (self, parameter_names, unique = True):
    own_name = self.make_name (parameter_names)
    tutil.add_unpacked_type ( own_name,
                              '''
                              {node}* next;
                              {Value} val;'''.format (node=own_name, Value=parameter_names[0]),
                              unique,
                              8)

# technically <Value, Hash = blz::hash<Value>, Equal =
# blz::equal_to<Value>, Allocator = blz::allocator<Value>>, but nobody
# ever sepcifies those.
class blz_unordered_set (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::unordered_set", ["Value"])
  def create_types (self, parameter_names, unique = True):
    node = tutil.create_template_and_make_name(blz_chained_hash_node(), parameter_names)
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names, 'blz::unordered_set::iterator'), # todo: blz::chained_hash_table_const_iterator<Node>
                                         '''
                                         {node}* node;
                                         {node}** bucket;
                                         {node}** end;'''.format (node=node),
                                         False)
    insert_result = tutil.create_template_and_make_name(blz_pair(), [iterator, 'bool'], False)
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names), # todo: blz::chained_hash_table<Traits>
                                         '''
                                         unsigned __int64 m_bucket_count;
                                         {node}** m_buckets;
                                         unsigned __int64 m_entry_count;
                                         float m_max_load_factor;'''.format (node=node),
                                         unique)

class blz_unordered_map (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::unordered_map", ["Key", "Value"])
  def create_types (self, parameter_names, unique = True):
    value = tutil.create_template_and_make_name(blz_pair(), parameter_names)
    node = tutil.create_template_and_make_name(blz_chained_hash_node(), [value])
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names, 'blz::unordered_map::iterator'), # todo: blz::chained_hash_table_const_iterator<Node>
                                         '''
                                         {node}* node;
                                         {node}** bucket;
                                         {node}** end;'''.format (node=node),
                                         False)
    insert_result = tutil.create_template_and_make_name(blz_pair(), [iterator, 'bool'], False)
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names), # todo: blz::chained_hash_table<Traits>
                                         '''
                                         unsigned __int64 m_bucket_count;
                                         {node}** m_buckets;
                                         unsigned __int64 m_entry_count;
                                         float m_max_load_factor;'''.format (node=node),
                                         unique)
