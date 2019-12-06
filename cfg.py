from pycfg.pycfg import PyCFG, CFGNode, slurp 
from list_modules import get_imports_from_file 

def traverse(cfgnode, funcs):
  #print(cfgnode)
  #print("Children: ", cfgnode.children)
  #print(cfgnode.source())

  # Add to path, instantiate biglist
  #path = path+[cfgnode]
  biglist = []
  routes = []
  # If call is made, iterate or determine built-in
  if len(cfgnode.calls) > 0:
    test = []
    for call in cfgnode.calls:
      try:
        test += funcs[call]
      except:
        #print("Built-in function ", call)
        pass
    for node in test:
      # routes holds all the possible routes the program could have taken
      routes += traverse(node, funcs)
  
  # If there's no children finish up calls and exit
  if len(cfgnode.children) == 0:
    #print("no children")

    # Magic list comprehensions to ignore prints and make sure for no redundancy
    for x in range(len(routes)):
      routes[x] = [x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"] + routes[x]
    if(len(routes) == 0):
      routes = [[x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"]]
    
    biglist = routes

    return biglist

  # Traverse children/all branches
  branches = []
  route = []
  for child in cfgnode.children:
    # Check if entering was already done in routes
    skip = False
    for call in cfgnode.calls:
      try:
        if funcs[call][0] == child:
          skip = True
          break
      except:
        pass
    if skip:
      continue

    # If returning to an iteration, we just exit the iteration (it's too hard to track!)
    if child.rid < cfgnode.rid and ((str(child.source()).split(':')[0] == "_for") or (str(child.source()).split(':')[0] == "_while")):
      route = traverse(child.children[-1], funcs)
      branches += [x for x in route if x not in branches]
      continue
    else:
      route = traverse(child, funcs)
      branches += [x for x in route if x not in branches]

  # Prepend with current call
  for x in range(len(routes)):
    routes[x] = [x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"] + routes[x]
  if(len(routes) == 0):
    routes = [[x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"]]
  
  # Create final list
  biglist = [x+y for x in routes for y in branches]
  if len(branches) == 0:
    biglist = routes

  return biglist

cfg = PyCFG()
cfg.gen_cfg(slurp("/mnt/c/Users/dylan/programming/6332/CFGAnalyzer/vulns/backdoor.py").strip())
cfg2 = PyCFG()
cfg2.gen_cfg(slurp("/mnt/c/Users/dylan/programming/6332/django/django/views/defaults.py").strip())
g = CFGNode.to_graph([])
totalfuncs = {}
totalfuncs.update(cfg.functions)
totalfuncs.update(cfg2.functions)
#print("CFG FUNCS: ")
#print(cfg.functions)
#print("CFG2 FUNCS: ")
#print(cfg2.functions)
#print("TOTALFUNCS: ")
#print(totalfuncs)
#print("END OF TOTAL FUNCS")
biglist = traverse(cfg2.functions['page_not_found'][0], totalfuncs)
for x in range(len(biglist)):
  print(biglist[x])
