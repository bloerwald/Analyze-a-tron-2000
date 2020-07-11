import gutil
import tcontainers
import tdbc
import tutil

def main():
  chosen_template = gutil.choose_one ('Template class',
                                      [cls.__name__ for cls in tutil.template_description.__subclasses__()])
  if not chosen_template:
    return
  template = globals()[chosen_template]()

  name_pref = chosen_template + '$'

  parameters = []
  for parameter in range (0, template.parameter_count()):
    ch_struct = ida_kernwin.choose_struc('Choose ' + name_pref + template.parameter_name (parameter))
    if not ch_struct:
      p = AskStr ("", template.parameter_name (parameter))
      if not p:
        return
      param = p
    else:
      param = ida_struct.get_struc_name(ch_struct.id)
    parameters.append (param)
    name_pref += '$' + param

  template.create_types (parameters)
main()
