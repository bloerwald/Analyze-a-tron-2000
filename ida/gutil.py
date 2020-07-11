import ida_kernwin

def choose_one(name, items):
  class SimpleChooser(ida_kernwin.Choose):
    def __init__(self, name, items):
      ida_kernwin.Choose.__init__(self,
                                  'Choose ' + name,
                                  [[name, 30]])
      self.items = [[item] for item in items]
      self.selection = None
    def OnGetSize(self):
      return len(self.items)
    def OnGetLine(self, n):
      return self.items[n]
  ch = SimpleChooser(name, items).Show(True)
  return items[ch] if ch != -1 else None
