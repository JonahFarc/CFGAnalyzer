from pycfg.pycfg import PyCFG, CFGNode, slurp 
from list_modules import get_imports_from_file 
import copy

def traverse(cfgnode, funcs, path=[]):
  #print(cfgnode)
  #print("Children: ", cfgnode.children)
  #print(cfgnode.source())

  # Add to path, instantiate biglist
  path = path+[cfgnode]
  biglist = []
  routes = []
  # If call is made, iterate or determine built-in
  if len(cfgnode.calls) > 0:
    test = []
    for call in cfgnode.calls:
      try:
        #if call == "recv":
        #  calls += ['recv']
        test += funcs[call]
      except:
        #print("Built-in function ", call)
        pass
    for node in test:
      # routes holds all the possible routes the program could have taken
      #routes += traverse(node, funcs, path)
      calls = traverse(node, funcs, path)
      biglist = biglist + [y for y in calls if y not in biglist and len(y) > 0]
  #print(calls)
  
  # If there's no children finish up calls and exit
  if len(cfgnode.children) == 0:
    #print("no children")

    # Magic list comprehensions. Seriously. I don't know how I wrote this.
    calls = [y for x in path for y in x.calls if y not in funcs.keys() and "print" not in y]

    if calls not in biglist:
      biglist = biglist + [calls]
    return biglist

  # Traverse both true and false branches
  branches = []
  route = []
  for child in cfgnode.children:
    # If returning to an iteration, we just exit the iteration (it's too hard to track!)
    if child.rid < cfgnode.rid and ((str(child.source()).split(':')[0] == "_for") or (str(child.source()).split(':')[0] == "_while")):
      calls = traverse(child.children[-1], funcs, path)
      #if len(route) > 1 and route not in branches:
      #  branches = branches + route
      biglist = biglist + [y for y in calls if y not in biglist and len(y) > 0]
      continue
    else:
      #route = traverse(child, funcs, path)
      calls = traverse(child, funcs, path)
      #if len(route) > 1 and route not in branches:
      #  branches = branches + route
      biglist = biglist + [y for y in calls if y not in biglist and len(y) > 0]

  if len(branches) > 1:
    print("Branches: ")
    print(branches)
    print()
  #biglist = biglist + [y for y in routes if y not in biglist and len(y) > 0]
  #print(biglist)
  return biglist
  # print("Calls: ", cfgnode.calls)
  # print("Regid: ", cfgnode.rid)
  # print("ast: ", cfgnode.ast_node.lineno)

cfg = PyCFG()
cfg.gen_cfg(slurp("/mnt/c/Users/dylan/programming/6332/CFGAnalyzer/vulns/backdoor.py").strip())
cfg2 = PyCFG()
cfg2.gen_cfg(slurp("/mnt/c/Users/dylan/programming/6332/django/django/views/defaults.py").strip())
g = CFGNode.to_graph([])
totalfuncs = {}
#print("CFG FUNCS: ")
#print(cfg.functions)
#print("CFG2 FUNCS: ")
#print(cfg2.functions)
#print("TOTALFUNCS: ")
totalfuncs.update(cfg.functions)
totalfuncs.update(cfg2.functions)
#print(totalfuncs)
#print(cfg)
#print("END OF TOTAL FUNCS")
biglist = traverse(cfg2.functions['page_not_found'][0], totalfuncs)
print(biglist)
for x in range(len(biglist)):
  print(biglist[x])
