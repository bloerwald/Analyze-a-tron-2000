import tutil

class blz_vector (tutil.template_description):
  def __init__ (self):
    tutil.template_description.__init__ (self, "blz::vector", ["T"])
  def create_types (self, parameter_names, unique = True):
    tutil.add_packed_type ( "_2_blz_vector",
                            "unsigned long long size; unsigned long long capacity;")
    tutil.add_packed_type ( self.make_name (parameter_names),
                            "%s* data; _2_blz_vector _2;" % (parameter_names[0]),
                            unique)
