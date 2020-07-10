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
