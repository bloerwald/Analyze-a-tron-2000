#! /usr/bin/env python

import dbd
import os
import sys
import argparse

def has_build(needle, builds):
  for build in builds:
    if isinstance(build, tuple):
      begin, end = build
      if begin.major != end.major or begin.minor != end.minor or begin.patch != end.patch or begin.build > end.build:
        continue # todo: implement
      while begin != end:
        if needle == str(begin):
          return True
        begin.build += 1
    else:
      if str(build) == needle:
        return True

  return False

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument( '--definitions', dest="definitions", type=str, required=True
                     , help="location of .dbd files")
  parser.add_argument( '--build', dest="build", type=str, required=True
                     , help="WoW build to select")
  args = parser.parse_args()

  #dbds = {}
  #dbds['AreaPOI'] = dbd.parse_dbd_file(os.path.join(args.definitions, "AreaPOI{}".format(dbd.file_suffix)))
  dbds = dbd.parse_dbd_directory(args.definitions)

  file_data = {}

  for name, parsed in dbds.items():
    file_data[name] = ""

    columns = {}
    for column in parsed.columns:
      columns[column.name] = column
    assert(len(columns)==len(parsed.columns))

    for definition in parsed.definitions:
      if not has_build (args.build, definition.builds):
        continue

      lines = []
      has_string = False
      for entry in definition.entries:
        meta = columns[entry.column]

        type_str = meta.type
        if type_str in ["uint", "int"]:
          type_str = '{}{}_t'.format (meta.type if not entry.is_unsigned else "uint", entry.int_width if entry.int_width else 32)
        elif type_str in ['string', 'locstring']:
          type_str = 'dbc_' + type_str
          has_string = True
        else:
          assert (not entry.int_width)
          assert (not meta.foreign)

        array_str = "[{}]".format(entry.array_size) if entry.array_size else ""

        name_str = entry.column

        comments = []

        merged_str_pattern = "  {} {}{}; {}"
        for annotation in entry.annotation:
          if annotation == "noninline":
            merged_str_pattern = "  // {} {}{}; {}"
            comments += ["non-inline field"]
          elif annotation == "id":
            pass
          else:
            comments += ["{}".format(annotation)]

        comments += [entry.comment] if entry.comment else []
        comments += [meta.comment] if meta.comment else []
        comments_str = ''
        if len (comments):
          comments_str = '// {}'.format (';'.join (comments).encode('ascii', 'backslashreplace'))

        lines += [merged_str_pattern.format(type_str, name_str, array_str, comments_str)]

      if 'table is sparse' in definition.comments and has_string:
        file_data[name] += '// omitting: is sparse and has string, the layout would be wrong!'
      else:
        for comment in definition.comments:
          file_data[name] += '// ' + str(comment.encode('ascii', 'backslashreplace')) + "\n\n"
        file_data[name] += "struct {}Rec {{\n".format(name)
        for line in lines:
          file_data[name] += line + "\n"
        file_data[name] += "};\n"

  print ('struct dbc_string { uint32_t _; };')
  print ('typedef dbc_string dbc_locstring;')

  for name, data in file_data.items():
    print ('//' + name)

    print ('#pragma pack (push, 1)')
    print (data)
    print ('#pragma pack (pop, 1)')

main()
