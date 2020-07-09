from idaapi import *
import ida_struct

def add_packed_type (name, decl, unique = False):
  if ida_struct.get_struc_id (name) != BADADDR:
    if unique:
      raise RuntimeError ("struct %s already exists" % (name))
  else:
    idc_parse_types ("""
      #pragma pack (push, 1)
      struct %s { %s };
      #pragma pack (pop, 1)""" % (name, decl), 0)
    import_type (cvar.idati, -1, name)
    print "## DECLARED ", name
  return name

def add_unpacked_type (name, decl, unique = False):
  if ida_struct.get_struc_id (name) != BADADDR:
    if unique:
      raise RuntimeError ("struct %s already exists" % (name))
  else:
    idc_parse_types ("""struct %s { %s };""" % (name, decl), 0)
    import_type (cvar.idati, -1, name)
    print "## DECLARED ", name
  return name

def maybe_make_dummy_type (name):
  if ida_struct.get_struc_id (name) == BADADDR:
    idc_parse_types ("struct %s;" % (name), 0)
    import_type (cvar.idati, -1, name)
  return name

def maybe_make_dummy_type_with_known_size (name, size):
  if ida_struct.get_struc_id (name) == BADADDR:
    idc_parse_types ("struct %s { char dummy[%s]; }" % (name, size), 0)
    import_type (cvar.idati, -1, name)
  return name

def maybe_make_templated_type (name, parameters):
  template = globals()[name]()
  template.create_types (parameters, False)
  return template.make_name (parameters)
def make_templated_type (name, parameters):
  template = globals()[name]()
  template.create_types (parameters, True)
  return template.make_name (parameters)

class template_description (object):
  def __init__ (self, name, parameters):
    object.__init__ (self)
    self.name = name
    self.parameters = parameters
  def parameter_count (self):
    return len (self.parameters)
  def parameter_name (self, index):
    return self.parameters[index]

  def make_name (self, parameter_names, name_override = ""):
    assert len (parameter_names) == self.parameter_count()
    name = ""
    if name_override == "":
      name = self.name
    else:
      name = name_override
    for parameter in parameter_names:
      name += "$" + parameter.replace (" const*", "_cptr").replace (" *", "_ptr").replace ("*", "_ptr").replace (" ", "_")
    return name

def create_template_and_make_name (template, parameters):
  template.create_types (parameters, False)
  return template.make_name (parameters)

def integral_for_bytes (bytes):
  known = {1: '__int8', 2: '__int16', 4: '__int32', 8: '__int64', 16: '__int128'}
  return known[bytes]

## todo: better abstraction? do them as plain blobs for now...
## class Function:
##   def __init__ (self, name = None, ret = None, args = None):
##     self.name = name
##     self.ret = ret
##     self.args = args
##   def as_field (self, fallback_name = None):
##     name = self.name or fallback_name
##     if not name:
##       raise Exception ('function.as_field without name and fallback name')
##     if not self.ret and not self.args:
##       return '_UNKNOWN* %s' % (name)
##     elif self.ret and self.args:
##       return '%s (__fastcall* %s) (%s)' % (ret, name, args)
##     else:
##       raise Exception ('function.as_field with either ret but not args or the other way around')
##
## def make_vtable (type, functions):
##   funs = ''
##   i = 0
##   for fun in functions:
##     funs += fun.as_field ('fun_%s;' % (i))
##     i += 1
##   add_packed_type ('vtable$%s' % (type), funs)
