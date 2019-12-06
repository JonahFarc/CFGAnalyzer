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
  noderoutes = []
  nodebiglist = []
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
      temp = traverse(node,funcs)
      routes += temp[0]
      noderoutes += temp[1]
      #routes = traverse(node, funcs)
  
  # If there's no children finish up calls and exit
  if len(cfgnode.children) == 0:
    #print("no children")

    # Magic list comprehensions to ignore prints and make sure for no redundancy
    for x in range(len(routes)):
      routes[x] = [x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"] + routes[x]
    if(len(routes) == 0):
      routes = [[x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"]]

    for x in range(len(noderoutes)):
      noderoutes[x] = [cfgnode for call in cfgnode.calls if call not in funcs.keys() and call is not "print"] + noderoutes[x]
    if(len(noderoutes) == 0):
      noderoutes = [[cfgnode for call in cfgnode.calls if call not in funcs.keys() and call is not "print"]]
    
    biglist = routes
    nodebiglist = noderoutes

    return biglist, nodebiglist

  # Traverse children/all branches
  branches = []
  route = []
  noderoute = []
  nodebranches = []
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
      route, noderoute = traverse(child.children[-1], funcs)
      branches += [x for x in route if x not in branches]
      nodebranches += [x for x in noderoute if x not in nodebranches]
      continue
    else:
      route, noderoute = traverse(child, funcs)
      branches += [x for x in route if x not in branches]
      nodebranches += [x for x in noderoute if x not in nodebranches]

  # Prepend with current call
  for x in range(len(routes)):
    routes[x] = [x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"] + routes[x]
  if(len(routes) == 0):
    routes = [[x for x in cfgnode.calls if x not in funcs.keys() and x is not "print"]]
  
  for x in range(len(noderoutes)):
    noderoutes[x] = [cfgnode for call in cfgnode.calls if call not in funcs.keys() and call is not "print"] + noderoutes[x]
  if(len(noderoutes) == 0):
    noderoutes = [[cfgnode for call in cfgnode.calls if call not in funcs.keys() and call is not "print"]]

  for x in range(len(noderoutes)):
    for y in range(len(noderoutes[x])-1):
      if noderoutes[x][y] == noderoutes[x][y+1]:
        noderoutes[x].remove(noderoutes[x][y])
        y-=1


  # Create final list
  biglist = [x+y for x in routes for y in branches]
  if len(branches) == 0:
    biglist = routes

  nodebiglist = [x+y for x in noderoutes for y in nodebranches]
  if len(nodebranches) == 0:
    nodebiglist = noderoutes

  return biglist, nodebiglist

def get_call_paths(test="/mnt/c/Users/dylan/programming/6332/django/django/views/defaults.py", imports=["/mnt/c/Users/dylan/programming/6332/CFGAnalyzer/vulns/backdoor.py"]):
  cfg_imports = []
  for path in imports:
    newcfg = PyCFG()
    newcfg.gen_cfg(slurp(path).strip())
    #cfg_imports.append(PyCFG().gen_cfg(slurp(path).strip()))
    cfg_imports.append(newcfg)
  cfg = PyCFG()
  cfg.gen_cfg(slurp(test).strip())
  g = CFGNode.to_graph([])
  totalfuncs = {}
  totalfuncs.update(cfg.functions)
  for cfg_import in cfg_imports:
    totalfuncs.update(cfg_import.functions)
  #print("CFG FUNCS: ")
  #print(cfg.functions)
  #print("CFG2 FUNCS: ")
  #print(cfg2.functions)
  #print("TOTALFUNCS: ")
  #print(totalfuncs)
  #print("END OF TOTAL FUNCS")
  biglist, nodebiglist = traverse(cfg.functions['page_not_found'][0], totalfuncs)
  print("Call paths: ")
  for x in range(len(biglist)):
    print(biglist[x])
  return biglist, nodebiglist
