import tutil

class blz_vector (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::vector", ["T"])
  def create_types (self, parameter_names, unique = True):
    p2 = tutil.add_packed_type ( "_2_blz_vector",
                                 "unsigned long long size; unsigned long long capacity;")
    tutil.add_packed_type ( self.make_name (parameter_names),
                            "%s* data; %s _2;" % (parameter_names[0], p2),
                            unique)

blz_string = tutil.add_packed_type ('blz::string',
                                    """
                                    char* data;
                                    unsigned long long size;
                                    unsigned long long capacity;
                                    char in_situ[16];""")

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
                              {Value} payload;'''.format (node=own_name, Value=parameter_names[0]),
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
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names, 'blz::unordered_set::iterator'),
                                         '''
                                         {node}* element;
                                         {node}** bucket_with_element;
                                         {node}** last_bucket;'''.format (node=node),
                                         False)
    insert_result = tutil.create_template_and_make_name(blz_pair(), [iterator, 'bool'], False)
    iterator = tutil.add_unpacked_type ( self.make_name (parameter_names),
                                         '''
                                         unsigned __int64 num_buckets;
                                         {node}** m_buckets;
                                         unsigned __int64 total_elements;
                                         float elem_per_bucket_threshold;'''.format (node=node),
                                         unique)
